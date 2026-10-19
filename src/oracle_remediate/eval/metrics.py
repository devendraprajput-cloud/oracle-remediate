"""Evaluation metrics (paper Section IV.B/IV.E).

RQ1  Pass@k with the unbiased estimator of Chen et al. (2021):
         pass@k = E[ 1 - C(n-c, k) / C(n, k) ]
     n = samples per finding (paper: n=10), c = samples that pass the verifier
     AND restore the invariant (here: L1 = L2 = L3 = 1).
RQ2  raw unsafe-output rate and the fraction caught before execution.  A
     *false negative* needs ground truth independent of Layer 1 -- supply DBA
     labels (``--labels``); without labels only the Layer-1-detectable rate is
     reported and is marked as such.
RQ4  rollback fidelity: fraction of verified remediations with L_RB = 1.
Also: Cohen's kappa (two annotators), 95% CI over independent runs, and the
two-criterion threshold calibration of Section III.D-3.
"""

from __future__ import annotations

import csv
import json
import math
import statistics
from pathlib import Path
from typing import Any

import numpy as np


def pass_at_k(n: int, c: int, k: int) -> float:
    """Numerically stable unbiased estimator (Chen et al., 2021)."""
    if n < 1 or k < 1 or k > n:
        raise ValueError("require 1 <= k <= n")
    if n - c < k:
        return 1.0
    return float(1.0 - np.prod(1.0 - k / np.arange(n - c + 1, n + 1)))


def cohen_kappa(a: list[Any], b: list[Any]) -> float:
    if len(a) != len(b) or not a:
        raise ValueError("annotation lists must be non-empty and equal length")
    labels = sorted(set(a) | set(b), key=str)
    n = len(a)
    po = sum(x == y for x, y in zip(a, b)) / n
    pe = sum((a.count(lbl) / n) * (b.count(lbl) / n) for lbl in labels)
    return 1.0 if pe == 1 else (po - pe) / (1 - pe)


_T975 = {1: 12.706, 2: 4.303, 3: 3.182, 4: 2.776, 5: 2.571, 6: 2.447, 7: 2.365, 8: 2.306, 9: 2.262, 10: 2.228,
         11: 2.201, 12: 2.179, 13: 2.160, 14: 2.145, 15: 2.131, 20: 2.086, 25: 2.060, 30: 2.042}


def mean_ci95(values: list[float]) -> dict[str, float]:
    """Mean and two-sided 95% t-interval (paper: five independent benchmark runs)."""
    n = len(values)
    if n == 0:
        return {"mean": float("nan"), "lo": float("nan"), "hi": float("nan"), "n": 0}
    m = statistics.fmean(values)
    if n == 1:
        return {"mean": m, "lo": m, "hi": m, "n": 1}
    df = n - 1
    t = _T975.get(df) or _T975[max(k for k in _T975 if k <= df)] if df <= 30 else 1.96
    half = t * statistics.stdev(values) / math.sqrt(n)
    return {"mean": m, "lo": m - half, "hi": m + half, "n": n}


def load_run(path: str | Path) -> dict[str, Any]:
    p = Path(path)
    if p.is_dir():
        p = p / "run.json"
    return json.loads(p.read_text())


def load_labels(path: str | Path | None) -> dict[tuple[str, int], int]:
    """CSV: finding_id,sample_index,unsafe (1/0) -- independent DBA annotation."""
    if not path:
        return {}
    with Path(path).open() as fh:
        return {(r["finding_id"], int(r["sample_index"])): int(r["unsafe"]) for r in csv.DictReader(fh)}


def evaluate_run(run: dict[str, Any], ks: tuple[int, ...] = (1, 3, 5),
                 labels: dict[tuple[str, int], int] | None = None) -> dict[str, Any]:
    outcomes = [o for o in run["outcomes"] if o["status"] == "processed"]
    per_k: dict[int, list[float]] = {k: [] for k in ks}
    unsafe_total = unsafe_caught = samples = 0
    fn = tp_labels = 0
    verified = rb_ok = 0
    per_class: dict[str, list[float]] = {}
    for o in outcomes:
        evs = o.get("candidate_evaluations") or []
        fid = o["finding"]["finding_id"]
        if evs:
            n = len(evs)
            c = sum(1 for e in evs if e.get("valid") and e["L1"] and e["L2"] and e["L3"])
            for k in ks:
                if k <= n:
                    per_k[k].append(pass_at_k(n, c, k))
            per_class.setdefault(o.get("control_class") or "?", []).append(pass_at_k(n, c, 1))
            for e in evs:
                samples += 1
                if e.get("valid") and e.get("unsafe"):
                    unsafe_total += 1
                    unsafe_caught += 1 if e["L1"] == 0 else 0
                lab = (labels or {}).get((fid, e["sample_index"]))
                if lab == 1:
                    tp_labels += 1
                    if e.get("valid") and e.get("L1") == 1 and e.get("L3") == 1 and e.get("L_RB") == 1:
                        fn += 1  # unsafe per human label, not caught by any hard gate
        v = o.get("verifier") or {}
        if v and v["L1"]["passed"] and v["L2"]["passed"] and v["L3"]["passed"]:
            verified += 1
            rb_ok += int((o.get("rollback") or {}).get("L_RB", {}).get("passed", 0))
    res: dict[str, Any] = {
        "findings_processed": len(outcomes),
        "pass_at_k": {f"pass@{k}": (round(statistics.fmean(v), 4) if v else None) for k, v in per_k.items()},
        "pass_at_1_by_class": {k: round(statistics.fmean(v), 4) for k, v in sorted(per_class.items())},
        "safety": {
            "samples": samples,
            "raw_unsafe_rate_layer1_detectable": round(unsafe_total / samples, 4) if samples else None,
            "caught_before_execution": round(unsafe_caught / unsafe_total, 4) if unsafe_total else None,
            "note": "without --labels, 'unsafe' is defined by the Layer-1 forbidden set (not independent ground truth)",
        },
        "rollback_fidelity": round(rb_ok / verified, 4) if verified else None,
        "verified_remediations": verified,
        "dispositions": run["summary"]["dispositions"],
    }
    if labels:
        res["safety"]["labelled_unsafe"] = tp_labels
        res["safety"]["false_negative_rate"] = round(fn / tp_labels, 4) if tp_labels else None
    if not any(per_k.values()):
        res["pass_at_k_note"] = "no candidate_evaluations: re-run with --eval to compute Pass@k"
    return res


def aggregate_runs(results: list[dict[str, Any]]) -> dict[str, Any]:
    keys = ["pass@1", "pass@3", "pass@5"]
    out = {}
    for k in keys:
        vals = [r["pass_at_k"].get(k) for r in results if r["pass_at_k"].get(k) is not None]
        out[k] = mean_ci95(vals)
    rf = [r["rollback_fidelity"] for r in results if r.get("rollback_fidelity") is not None]
    out["rollback_fidelity"] = mean_ci95(rf)
    return out


def calibrate_thresholds(points: list[tuple[float, bool]], grid_step: float = 0.01) -> dict[str, Any]:
    """Two-criterion calibration (paper III.D-3) on held-out (C, correct) pairs.

    tau_auto  : lowest value with zero false auto-applies (no incorrect item with C >= tau_auto)
    tau_review: lowest value <= tau_auto such that the review band [tau_review, tau_auto) holds no
                incorrect item.  The paper's wording admits more than one reading; this is the literal
                one -- see docs/DESIGN_NOTES.md (D6).
    """
    grid = [round(i * grid_step, 4) for i in range(int(1 / grid_step) + 1)]
    bad = [c for c, ok in points if not ok]
    tau_auto = next((t for t in grid if all(c < t for c in bad)), 1.0)
    tau_review = next((t for t in grid if t <= tau_auto and all(not (t <= c < tau_auto) for c in bad)), tau_auto)
    auto = sum(1 for c, _ in points if c >= tau_auto)
    review = sum(1 for c, _ in points if tau_review <= c < tau_auto)
    return {"tau_auto": tau_auto, "tau_review": tau_review, "n": len(points), "incorrect": len(bad),
            "would_auto_apply": auto, "would_review": review, "would_reject": len(points) - auto - review}
