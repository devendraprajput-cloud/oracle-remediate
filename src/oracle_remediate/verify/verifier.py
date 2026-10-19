"""Safety Verification Layer + Rollback Verifier (paper Sections III.E and III.F).

Implements Listings 2 and 3 in one sandbox pass, in the order of the sequence
diagram (Fig. 1)::

    L1 static AST whitelist -> request snapshot -> L2 invariants (pre/post)
    -> L3 apply + dictionary delta -> round-trip rollback test -> L_RB

Every outcome is *recorded*; nothing here rejects a candidate.  The decision
policy (``scoring.policy``) alone decides.  One implementation choice is
stricter than the paper's pseudo-code: a candidate that fails Layer 1 is never
executed, not even in the sandbox (``never_execute_l1_failures``, default
True).  Its L2/L3/L_RB are then recorded as 0 with reason "not executed",
which makes the hard-floor rule reject it.  See docs/DESIGN_NOTES.md (D2).
"""

from __future__ import annotations

import random
from dataclasses import dataclass

from ..controls import Catalog, Control
from ..models import LayerResult, RollbackReport, VerifierReport
from .bisimulation import diff, expected_views
from .sandbox import Sandbox
from .sqltools import parse_script
from .static_check import static_check


@dataclass
class VerifierSettings:
    non_interference_sample: int = 8
    never_execute_l1_failures: bool = True
    seed: int = 7


def sample_other_controls(control: Control, catalog: Catalog, sandbox: Sandbox, k: int,
                          rng: random.Random) -> list[Control]:
    """Sampled subset of c' != c for the empirical non-interference check (III.E-2).

    Controls of the same class are preferred because they share dictionary views.
    """
    pool = [c for c in catalog if c.id != control.id and c.kind not in ("manual",) and sandbox.can_evaluate(c)]
    same = [c for c in pool if c.control_class == control.control_class]
    other = [c for c in pool if c.control_class != control.control_class]
    rng.shuffle(same)
    rng.shuffle(other)
    half = min(len(same), max(1, k // 2))
    return (same[:half] + other)[:k]


def verify_candidate(remediation_sql: str, rollback_sql: str, control: Control, catalog: Catalog,
                     sandbox: Sandbox, settings: VerifierSettings,
                     listeners: list[str] | None = None) -> tuple[VerifierReport, RollbackReport]:
    notes: list[str] = []
    # ---------------------------------------------------------------- Layer 1
    L1 = static_check(remediation_sql, rollback_sql, control, listeners)
    if L1.passed == 0 and settings.never_execute_l1_failures:
        skip = "not executed: Layer 1 failed and unsafe/out-of-scope statements are never run, even in the sandbox"
        z = LayerResult(0, skip)
        return (VerifierReport(L1, z, LayerResult(0, skip), executed=False, notes=[skip]),
                RollbackReport(LayerResult(0, skip)))

    rem = parse_script(remediation_sql)
    rb = parse_script(rollback_sql)
    rng = random.Random(f"{settings.seed}:{control.id}")
    others = sample_other_controls(control, catalog, sandbox, settings.non_interference_sample, rng)

    # ---------------------------------------------------------------- pre-state (S0)
    phi_pre = sandbox.evaluate_invariant(control)
    pre_other = {c.id: sandbox.evaluate_invariant(c) for c in others}
    S0 = sandbox.snapshot()

    # ---------------------------------------------------------------- apply remediation
    ex1 = sandbox.execute(rem)
    phi_post = sandbox.evaluate_invariant(control)
    S1 = sandbox.snapshot()

    # ---------------------------------------------------------------- Layer 2
    l2_reasons: list[str] = []
    if phi_pre is None:
        l2_reasons.append("invariant not evaluable in this sandbox")
    elif not phi_pre:
        l2_reasons.append("precondition failed: violation not present in sandbox (stale finding?)")
    if not ex1.ok:
        l2_reasons.append("remediation raised errors: " + "; ".join(ex1.errors[:3]))
    if phi_post is None or phi_post:
        l2_reasons.append(f"phi_c still violated after remediation ({len(phi_post or [])} rows)")
    changed_others = []
    for c in others:
        post = sandbox.evaluate_invariant(c)
        if post != pre_other[c.id]:
            changed_others.append(c.id)
    if changed_others:
        l2_reasons.append(f"non-interference: invariants changed for {changed_others}")
    L2 = LayerResult(0 if l2_reasons else 1, "; ".join(l2_reasons) or "phi_c restored; sampled invariants unchanged",
                     {"pre_rows": len(phi_pre or []), "post_rows": len(phi_post or []),
                      "sampled_controls": [c.id for c in others], "changed": changed_others})

    # ---------------------------------------------------------------- Layer 3
    delta = diff(S0, S1)
    exp = expected_views(rem, control)
    unexpected = sorted(delta.views - {e.upper() if not e.startswith("FILE:") else e for e in exp})
    if not ex1.ok:
        notes.append("Layer 3 evaluated on a partially applied remediation")
    L3 = LayerResult(1 if not unexpected else 0,
                     "dictionary delta within expected scope" if not unexpected
                     else f"unexpected dictionary change in {unexpected}",
                     {"expected": sorted(exp), "observed": sorted(delta.views), "delta": delta.to_dict()})

    # ---------------------------------------------------------------- round-trip rollback (S2)
    ex2 = sandbox.execute(rb)
    S2 = sandbox.snapshot()
    rb_delta = diff(S0, S2)
    rb_reasons = []
    if not ex2.ok:
        rb_reasons.append("rollback raised errors: " + "; ".join(ex2.errors[:3]))
    if not rb_delta.empty:
        rb_reasons.append(f"S0 != S2 in {sorted(rb_delta.views)}")
    L_RB = LayerResult(0 if rb_reasons else 1, "; ".join(rb_reasons) or "S0 == S2 (normalised)",
                       {"diff": rb_delta.to_dict()})

    report = VerifierReport(L1, L2, L3, executed=True, notes=notes)
    return report, RollbackReport(L_RB)
