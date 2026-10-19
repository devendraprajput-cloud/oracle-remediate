"""End-to-end orchestration of the per-finding loop in Fig. 1.

    remediate(F) -> context assembly (topology, dependencies, RAG, policy)
                 -> k self-consistency samples -> plurality candidate {fix, rollback}
                 -> L1 static -> snapshot clone -> L2 invariants -> L3 delta
                 -> round-trip rollback -> confidence C + hard floors
                 -> AUTO-APPLY | MANUAL-REVIEW | REJECT
"""

from __future__ import annotations

import csv
import datetime as dt
import hashlib
import json
import re
import time
from pathlib import Path
from typing import Any, Protocol

from .context.assembler import ContextAssembler
from .controls import Catalog, Control
from .llm.generator import RemediationGenerator
from .llm.prompt import build_request
from .models import Decision, Disposition, Finding, FindingOutcome, to_jsonable
from .scoring.confidence import ScoringSettings, confidence
from .scoring.policy import DecisionSettings, PolicyContext, decide
from .verify.sandbox import Sandbox
from .verify.verifier import VerifierSettings, verify_candidate


class SandboxProvider(Protocol):
    def open(self, control: Control, container: str, context: dict[str, Any]) -> Sandbox: ...


class SimulatedSandboxProvider:
    def __init__(self, db, listeners: list[str] | None = None):
        self.db = db
        self.listeners = listeners or ["LISTENER"]

    def open(self, control: Control, container: str, context: dict[str, Any]) -> Sandbox:
        from .sim.simulator import SimulatedSandbox
        return SimulatedSandbox(self.db, self.listeners)


class Pipeline:
    def __init__(self, catalog: Catalog, assembler: ContextAssembler, generator: RemediationGenerator,
                 sandbox_provider: SandboxProvider, policy: PolicyContext, scoring: ScoringSettings,
                 decision: DecisionSettings, verifier: VerifierSettings, *, listeners: list[str] | None = None,
                 applier=None, eval_mode: bool = False, n_eval: int = 10, output_dir: str | Path | None = None,
                 prompt_dir: Path | None = None, run_meta: dict[str, Any] | None = None,
                 price_per_mtok: dict[str, float | None] | None = None):
        self.catalog = catalog
        self.assembler = assembler
        self.generator = generator
        self.sandboxes = sandbox_provider
        self.policy = policy
        self.scoring = scoring
        self.decision = decision
        self.verifier = verifier
        self.listeners = listeners or ["LISTENER"]
        self.applier = applier
        self.eval_mode = eval_mode
        self.n_eval = n_eval
        self.prompt_dir = prompt_dir
        self.run_meta = run_meta or {}
        self.price = price_per_mtok or {}
        stamp = dt.datetime.now().strftime("%Y%m%dT%H%M%S")
        self.run_dir = Path(output_dir or "runs") / f"run-{stamp}"

    # ------------------------------------------------------------------ public
    def run(self, findings: list[Finding]) -> dict[str, Any]:
        self.run_dir.mkdir(parents=True, exist_ok=True)
        t0 = time.time()
        outcomes = [self.process(f) for f in findings]
        summary = self._summarise(outcomes, time.time() - t0)
        (self.run_dir / "run.json").write_text(json.dumps(
            {"meta": self.run_meta, "summary": summary, "outcomes": [to_jsonable(o) for o in outcomes]},
            indent=1, default=str))
        (self.run_dir / "summary.md").write_text(render_summary_md(summary, outcomes))
        self._write_csv(outcomes)
        summary["run_dir"] = str(self.run_dir)
        return summary

    def process(self, finding: Finding) -> FindingOutcome:
        timings: dict[str, float] = {}
        control = self.catalog.get(finding.control_id)
        if control is None:
            return self._finish(FindingOutcome(finding, "unknown_control", Decision(
                Disposition.MANUAL_REVIEW, None, reasons=[f"control {finding.control_id!r} not in catalog"])))
        exc = self.policy.exception_for(control.id, finding.container)
        if exc:
            return self._finish(FindingOutcome(finding, "excepted", Decision(
                Disposition.REJECT, None, reasons=[f"approved policy exception: {exc.get('reason', '')} "
                                                   f"(expires {exc.get('expires', 'never')}); no remediation generated"]),
                control.control_class))
        if not control.in_automated_scope:
            return self._finish(FindingOutcome(finding, "out_of_scope", Decision(
                Disposition.MANUAL_REVIEW, None,
                reasons=["out of automated scope: no invertible rollback exists for this control "
                         "(paper Section III.F); routed to manual review"]), control.control_class))

        t = time.time()
        ctx = self.assembler.assemble(finding, control)
        timings["context_s"] = time.time() - t
        request = build_request(finding, control, ctx, self.prompt_dir)
        t = time.time()
        gen = self.generator.generate(request, self.n_eval if self.eval_mode else None)
        timings["generation_s"] = time.time() - t
        summary_ctx = _context_summary(ctx)
        if gen.plurality is None:
            return self._finish(FindingOutcome(finding, "generation_failed", Decision(
                Disposition.REJECT, None, reasons=["no sample satisfied the output schema"]), control.control_class,
                summary_ctx, gen, timings=timings))

        cand = gen.plurality
        t = time.time()
        ver, rb = self._verify(cand.remediation_sql, cand.rollback_sql, control, finding, ctx)
        timings["verification_s"] = time.time() - t

        evals: list[dict[str, Any]] = []
        if self.eval_mode:
            t = time.time()
            evals = self._evaluate_all(gen, control, finding, ctx, (cand.canonical, ver, rb))
            timings["eval_verification_s"] = time.time() - t

        layers = {"L1": ver.L1.passed, "L2": ver.L2.passed, "L3": ver.L3.passed, "L_RB": rb.L_RB.passed}
        conf = confidence(gen.agreement, layers["L1"], layers["L2"], layers["L3"], layers["L_RB"], cand.risk_level,
                          self.scoring)
        review_reasons = self._review_reasons(control, finding, ctx, cand.remediation_sql)
        decision = decide(conf, layers, self.decision, bool(review_reasons), review_reasons)
        outcome = FindingOutcome(finding, "processed", decision, control.control_class, summary_ctx, gen, ver, rb,
                                 evals, timings=timings)
        if decision.disposition is Disposition.AUTO_APPLY and self.applier is not None:
            outcome.apply_result = self.applier.apply(outcome, control)
        return self._finish(outcome)

    # ------------------------------------------------------------------ helpers
    def _verify(self, rem: str, rb: str, control: Control, finding: Finding, ctx: dict[str, Any]):
        """Run the verifier; an unexpected error becomes an explicit failure, never a pass."""
        try:
            with self.sandboxes.open(control, finding.container, ctx) as sb:
                return verify_candidate(rem, rb, control, self.catalog, sb, self.verifier, self.listeners)
        except Exception as e:  # noqa: BLE001
            from .models import LayerResult, RollbackReport, VerifierReport
            from .verify.static_check import static_check
            why = f"verification error: {type(e).__name__}: {str(e).splitlines()[0] if str(e) else ''}"
            z = LayerResult(0, why)
            return (VerifierReport(static_check(rem, rb, control, self.listeners), z, LayerResult(0, why),
                                   executed=False, notes=[why]), RollbackReport(LayerResult(0, why)))

    def _evaluate_all(self, gen, control, finding, ctx, plurality_result) -> list[dict[str, Any]]:
        """Verify every distinct candidate (needed for Pass@k's c, paper IV.E)."""
        cache: dict[str, tuple] = {plurality_result[0]: plurality_result[1:]}
        out = []
        for c in gen.candidates:
            if not c.valid:
                out.append({"sample_index": c.sample_index, "valid": False, "error": c.parse_error})
                continue
            if c.canonical not in cache:
                cache[c.canonical] = self._verify(c.remediation_sql, c.rollback_sql, control, finding, ctx)
            v, r = cache[c.canonical]
            out.append({"sample_index": c.sample_index, "valid": True,
                        "canonical_hash": hashlib.sha1(c.canonical.encode()).hexdigest()[:10],
                        "L1": v.L1.passed, "L2": v.L2.passed, "L3": v.L3.passed, "L_RB": r.L_RB.passed,
                        "unsafe": any(x.startswith(("remediation: UnsafeStatement", "rollback: UnsafeStatement"))
                                      for x in v.L1.evidence.get("violations", [])),
                        "risk_level": c.risk_level})
        return out

    def _review_reasons(self, control: Control, finding: Finding, ctx: dict[str, Any], sql: str) -> list[str]:
        reasons = []
        if control.review_only:
            reasons.append("control marked review-only (SYSDBA/SYSTEM/audit-subsystem class)")
        if control.id in self.policy.review_only_controls:
            reasons.append("policy file marks this control review-only")
        pc = (ctx.get("dependency") or {}).get("parameter") if isinstance(ctx.get("dependency"), dict) else None
        if control.kind == "parameter":
            static = (str(pc.get("issys_modifiable", "")).upper() == "FALSE") if pc else control.requires_restart
            if static:
                reasons.append("static parameter: effect and invariant only verifiable after instance restart")
        words = set(re.findall(r"[A-Z0-9_$#]+", sql.upper()))
        touched = sorted(words & set(self.policy.service_accounts))
        if touched:
            reasons.append(f"touches whitelisted service account(s) {touched}")
        return reasons

    def _finish(self, o: FindingOutcome) -> FindingOutcome:
        d = self.run_dir / "findings" / _safe_name(o.finding.finding_id)
        d.mkdir(parents=True, exist_ok=True)
        o.artifact_dir = str(d)
        disp = o.decision.disposition.value
        conf = o.decision.confidence.C if o.decision.confidence else None
        header = (f"-- ORACLE-REMEDIATE | control {o.finding.control_id} | container {o.finding.container}\n"
                  f"-- disposition: {disp} | confidence: {conf}\n"
                  f"-- generated: {dt.datetime.now().isoformat(timespec='seconds')}\n")
        if o.decision.disposition is not Disposition.AUTO_APPLY:
            header += "-- NOT APPROVED FOR AUTOMATIC EXECUTION. Review before use.\n"
        if o.generation and o.generation.plurality and o.decision.disposition is not Disposition.REJECT:
            p = o.generation.plurality
            (d / "remediation.sql").write_text(header + p.remediation_sql.strip() + "\n")
            (d / "rollback.sql").write_text(header + p.rollback_sql.strip() + "\n")
            (d / "verification.sql").write_text(header + (p.verification_sql or "").strip() + "\n")
        (d / "decision.json").write_text(json.dumps(to_jsonable(o), indent=1, default=str))
        (d / "rationale.md").write_text(render_rationale(o))
        return o

    def _summarise(self, outcomes: list[FindingOutcome], wall: float) -> dict[str, Any]:
        disp: dict[str, int] = {}
        for o in outcomes:
            disp[o.decision.disposition.value] = disp.get(o.decision.disposition.value, 0) + 1
        processed = [o for o in outcomes if o.status == "processed"]
        tin = sum(o.generation.usage.input_tokens for o in outcomes if o.generation)
        tout = sum(o.generation.usage.output_tokens for o in outcomes if o.generation)
        cost = None
        if self.price.get("input") is not None and self.price.get("output") is not None:
            cost = round(tin / 1e6 * float(self.price["input"]) + tout / 1e6 * float(self.price["output"]), 4)
        gens = [o.generation for o in outcomes if o.generation]
        return {
            "findings": len(outcomes),
            "dispositions": disp,
            "status": {s: sum(1 for o in outcomes if o.status == s) for s in sorted({o.status for o in outcomes})},
            "processed": len(processed),
            "mean_confidence": round(sum(o.decision.confidence.C for o in processed if o.decision.confidence)
                                     / max(1, len(processed)), 4),
            "layer_pass_rates": {k: round(sum(getattr(o.verifier, k).passed for o in processed if o.verifier)
                                          / max(1, len(processed)), 4) for k in ("L1", "L2", "L3")} | {
                "L_RB": round(sum(o.rollback.L_RB.passed for o in processed if o.rollback) / max(1, len(processed)), 4)},
            "hard_floor_rejects": sum(1 for o in processed if o.decision.hard_floor),
            "tokens": {"input": tin, "output": tout,
                       "mean_per_finding": round((tin + tout) / max(1, len(gens)), 1)},
            "usd_cost": cost,
            "temperature_requested": gens[0].temperature_requested if gens else None,
            "temperature_applied": sorted({str(g.temperature_applied) for g in gens}),
            "wall_clock_s": round(wall, 3),
            "mean_wall_clock_per_finding_s": round(wall / max(1, len(outcomes)), 4),
            "eval_mode": self.eval_mode,
        }

    def _write_csv(self, outcomes: list[FindingOutcome]) -> None:
        with (self.run_dir / "dispositions.csv").open("w", newline="") as fh:
            w = csv.writer(fh)
            w.writerow(["finding_id", "control_id", "container", "status", "disposition", "C", "A", "V", "L1", "L2",
                        "L3", "L_RB", "R", "hard_floor", "overrides"])
            for o in outcomes:
                c = o.decision.confidence
                w.writerow([o.finding.finding_id, o.finding.control_id, o.finding.container, o.status,
                            o.decision.disposition.value, c.C if c else "", c.A if c else "", c.V if c else "",
                            o.verifier.L1.passed if o.verifier else "", o.verifier.L2.passed if o.verifier else "",
                            o.verifier.L3.passed if o.verifier else "", o.rollback.L_RB.passed if o.rollback else "",
                            c.R if c else "", ";".join(o.decision.hard_floor), ";".join(o.decision.overrides)])


def _safe_name(s: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.$#-]+", "_", s)


def _context_summary(ctx: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {"flags": ctx.get("flags"), "timings": ctx.get("timings")}
    topo = ctx.get("topology")
    if isinstance(topo, dict):
        out["topology"] = {k: topo.get(k) for k in ("is_rac", "is_exadata", "dataguard", "exadata_cells")}
        out["topology"]["instances"] = len(topo.get("instances", []))
    if isinstance(ctx.get("documentation"), list):
        out["documentation_sources"] = [d["source"] for d in ctx["documentation"]]
    if isinstance(ctx.get("dependency"), dict):
        out["dependency_keys"] = sorted(k for k in ctx["dependency"] if k != "source")
    return out


def render_rationale(o: FindingOutcome) -> str:
    lines = [f"# {o.finding.control_id} -- {o.finding.title}", "",
             f"* container: `{o.finding.container}`", f"* observed: `{o.finding.observed_value}`",
             f"* expected: `{o.finding.expected_value}`", f"* status: **{o.status}**",
             f"* disposition: **{o.decision.disposition.value}**", ""]
    c = o.decision.confidence
    if c:
        lines += ["## Confidence breakdown", "", "| A | V | L_RB | R | C |", "|---|---|---|---|---|",
                  f"| {c.A:.2f} | {c.V:.2f} | {c.L_RB} | {c.R:.2f} | **{c.C:.3f}** |", ""]
    if o.verifier:
        lines += ["## Verification", ""]
        for name, lr in (("L1 static AST", o.verifier.L1), ("L2 invariants", o.verifier.L2),
                         ("L3 sandbox bisimulation", o.verifier.L3)):
            lines.append(f"* {name}: {'PASS' if lr.passed else 'FAIL'} -- {lr.detail}")
        if o.rollback:
            lines.append(f"* L_RB round-trip rollback: {'PASS' if o.rollback.L_RB.passed else 'FAIL'} -- "
                         f"{o.rollback.L_RB.detail}")
        lines.append("")
    lines += ["## Decision", ""] + [f"* {r}" for r in o.decision.reasons + o.decision.overrides]
    if o.generation and o.generation.plurality:
        p = o.generation.plurality
        lines += ["", "## Model rationale", "", p.rationale or "-", "", f"risk_level: `{p.risk_level}`", ""]
        if p.assumptions:
            lines += ["Assumptions:"] + [f"* {a}" for a in p.assumptions]
        lines += ["", f"Agreement: {o.generation.plurality_count}/{len(o.generation.candidates)} samples "
                      f"(A={o.generation.agreement:.2f}); model `{o.generation.model}`; "
                      f"temperature requested {o.generation.temperature_requested}, applied "
                      f"{o.generation.temperature_applied}"]
    if o.apply_result:
        lines += ["", "## Production apply", "", "```json", json.dumps(o.apply_result, indent=1), "```"]
    return "\n".join(lines) + "\n"


def render_summary_md(s: dict[str, Any], outcomes: list[FindingOutcome]) -> str:
    rows = ["| finding | status | disposition | C | L1 | L2 | L3 | L_RB |", "|---|---|---|---|---|---|---|---|"]
    for o in outcomes:
        c = o.decision.confidence
        v = o.verifier
        rows.append(f"| {o.finding.control_id} @ {o.finding.container} | {o.status} | {o.decision.disposition.value} | "
                    f"{f'{c.C:.3f}' if c else '-'} | {v.L1.passed if v else '-'} | {v.L2.passed if v else '-'} | "
                    f"{v.L3.passed if v else '-'} | {o.rollback.L_RB.passed if o.rollback else '-'} |")
    return ("# ORACLE-REMEDIATE run summary\n\n```json\n" + json.dumps(s, indent=1, default=str) + "\n```\n\n"
            + "\n".join(rows) + "\n")
