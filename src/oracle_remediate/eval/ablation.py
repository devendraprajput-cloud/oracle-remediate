"""RQ3 context-class ablation and the zero-shot baseline (paper Sections IV.B, IV.D).

Variants (each run in evaluation mode on identical findings and seeds):
  full              all four context classes
  -topology, -dependency, -documentation, -policy   one class removed
  zero_shot         no context classes (baseline (c) of Section IV.D)

Baselines (a) CIS verbatim prose and (b) DBSAT recommendations are prose, not
executable code; they are evaluated by DBA annotation, not by this runner.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from ..config import Config
from ..factory import build_pipeline
from ..ingestion.findings import read_findings
from . import metrics

CLASSES = ["topology", "dependency", "documentation", "policy"]


def variants() -> dict[str, dict[str, bool]]:
    v = {"full": {c: True for c in CLASSES}}
    for c in CLASSES:
        v[f"-{c}"] = {x: x != c for x in CLASSES}
    v["zero_shot"] = {c: False for c in CLASSES}
    return v


def run_ablation(config, findings_path: str | None, out: str, topology: str | None = None,
                 findings=None) -> dict[str, Any]:
    results: dict[str, Any] = {}
    for name, flags in variants().items():
        over: dict[str, Any] = {"context": flags}
        if topology:
            over["sandbox"] = {"topology_profile": topology}
        cfg = Config.load(config, over)
        fs = findings if findings is not None else read_findings(findings_path)
        pipe, _ = build_pipeline(cfg, eval_mode=True, output_dir=str(Path(out) / name.strip("-")))
        pipe.run(fs)
        res = metrics.evaluate_run(metrics.load_run(pipe.run_dir))
        results[name] = {"pass@1": res["pass_at_k"]["pass@1"], "pass@5": res["pass_at_k"]["pass@5"],
                         "rollback_fidelity": res["rollback_fidelity"], "dispositions": res["dispositions"],
                         "run_dir": str(pipe.run_dir)}
    full = results["full"]["pass@1"] or 0.0
    for r in results.values():
        r["delta_pass@1_vs_full"] = None if r["pass@1"] is None else round(r["pass@1"] - full, 4)
    return results
