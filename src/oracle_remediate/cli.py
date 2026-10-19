"""``orarem`` command-line interface."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__
from .config import Config, credentials
from .controls import Catalog


def _cfg(args, extra: dict | None = None) -> Config:
    over = extra or {}
    if getattr(args, "topology", None):
        over.setdefault("sandbox", {})["topology_profile"] = args.topology
    return Config.load(args.config, over)


def _print(obj) -> None:
    print(json.dumps(obj, indent=1, default=str))


# ------------------------------------------------------------------ audit
def cmd_audit(args) -> int:
    from .audit.auditor import OracleAuditTarget, SimulatedAuditTarget, run_audit
    from .ingestion.findings import write_findings
    cfg = _cfg(args)
    catalog = Catalog.load(cfg.path("catalog"))
    if args.from_spool:
        findings = findings_from_spool(Path(args.from_spool), catalog, args.container or "CDB$ROOT")
    elif cfg.get("sandbox.mode") == "simulated":
        from .sim.scenarios import build_database
        target = SimulatedAuditTarget(build_database(cfg.get("sandbox.topology_profile")), cfg.get("files.listeners"))
        findings = run_audit(catalog, target)
    else:
        from .db.oracle import OracleClient
        t = cfg.get("target")
        client = OracleClient(*credentials(t), sysdba=bool(t.get("sysdba")))
        files = {"sqlnet_ora": cfg.get("files.sqlnet_ora"), "listener_ora": cfg.get("files.listener_ora")}
        findings = run_audit(catalog, OracleAuditTarget(client, files, cfg.get("files.listeners"),
                                                        args.containers.split(",") if args.containers else
                                                        cfg.get("target.containers")))
    write_findings(findings, args.out)
    print(f"{len(findings)} findings written to {args.out}")
    return 0


def findings_from_spool(path: Path, catalog: Catalog, container: str):
    from .models import Finding
    rows: dict[str, list[str]] = {}
    for line in path.read_text(errors="replace").splitlines():
        if "|" not in line:
            continue
        parts = [p.strip() for p in line.split("|")]
        if catalog.get(parts[0]):
            rows.setdefault(parts[0], []).append("|".join(parts[1:]))
    out = []
    for cid, rs in rows.items():
        c = catalog.get(cid)
        out.append(Finding(cid, c.title, "; ".join(rs[:6]), "", [container], [r.split("|")[0] for r in rs],
                           c.invariant() or "", c.cis_id, "sqlplus-spool"))
    return out


# ------------------------------------------------------------------ remediate / demo
def cmd_remediate(args) -> int:
    from .factory import build_pipeline
    from .ingestion.findings import read_findings
    cfg = _cfg(args)
    findings = read_findings(args.findings, args.mapping)
    if args.only:
        wanted = set(args.only.split(","))
        findings = [f for f in findings if f.control_id in wanted]
    pipe, _ = build_pipeline(cfg, eval_mode=args.eval, allow_apply=args.apply, output_dir=args.out)
    if args.apply and not cfg.get("apply.enabled"):
        print("NOTE: --apply given but apply.enabled is false in config; running as dry run.", file=sys.stderr)
    summary = pipe.run(findings)
    _print(summary)
    return 0


def cmd_demo(args) -> int:
    from .audit.auditor import SimulatedAuditTarget, run_audit
    from .factory import build_pipeline
    from .ingestion.findings import write_findings
    over = {"sandbox": {"mode": "simulated", "topology_profile": args.topology},
            "llm": {"backend": "mock", "model": "mock-remediator"}}
    if args.no_noise:
        over["llm"]["mock"] = {"p_variant": 0.0, "p_wrong": 0.0, "p_unsafe": 0.0}
    cfg = Config.load(args.config, over)
    pipe, db = build_pipeline(cfg, eval_mode=args.eval, output_dir=args.out)
    catalog = pipe.catalog
    findings = run_audit(catalog, SimulatedAuditTarget(db, cfg.get("files.listeners")))
    pipe.run_dir.mkdir(parents=True, exist_ok=True)
    write_findings(findings, pipe.run_dir / "findings.csv")
    summary = pipe.run(findings)
    _print(summary)
    print(f"\nArtifacts: {pipe.run_dir}  (summary.md, run.json, findings/<id>/...)")
    return 0


# ------------------------------------------------------------------ catalog
def cmd_catalog(args) -> int:
    cfg = _cfg(args)
    catalog = Catalog.load(cfg.path("catalog"))
    if args.action == "validate":
        _print(catalog.completeness())
    elif args.action == "list":
        for c in catalog:
            print(f"{c.id:42s} {c.cis_id or '-':8s} {c.control_class:10s} {c.kind:20s} "
                  f"{'auto' if c.in_automated_scope else 'manual'}  {c.title}")
    elif args.action == "show":
        c = catalog.get(args.id)
        if not c:
            print(f"unknown control {args.id}", file=sys.stderr)
            return 2
        _print(c.__dict__ | {"invariant": c.invariant()})
    elif args.action == "export-sql":
        lines = ["SET PAGESIZE 0 LINESIZE 32767 TRIMSPOOL ON FEEDBACK OFF HEADING OFF VERIFY OFF",
                 "SET COLSEP '|'", "WHENEVER SQLERROR CONTINUE"]
        for c in catalog:
            sql = c.invariant()
            if sql:
                lines.append(f"PROMPT -- {c.id}")
                lines.append(f"SELECT '{c.id}' AS control_id, q.* FROM (\n{sql}\n) q;")
        text = "\n".join(lines) + "\n"
        if args.out:
            Path(args.out).write_text(text)
            print(f"wrote {args.out}")
        else:
            print(text)
    return 0


# ------------------------------------------------------------------ rag
def cmd_rag(args) -> int:
    from .factory import build_retriever
    cfg = _cfg(args, {"context": {"documentation": True}})
    if args.action == "ingest":
        r = build_retriever(cfg)
        if cfg.get("rag.store") == "oracle23ai":
            r.store.create_schema()
        n = r.ingest_dir(args.path, int(cfg.get("rag.chunk_chars")))
        print(f"ingested {n} chunks from {args.path} into {cfg.get('rag.store')}")
    else:
        from .models import Finding
        catalog = Catalog.load(cfg.path("catalog"))
        c = catalog.get(args.control)
        r = build_retriever(cfg)
        for h in r.retrieve(c, Finding(c.id, c.title, args.observed or "", "")):
            print(f"[{h['score']:.3f}] {h['source']}: {h['text'][:160].replace(chr(10), ' ')}")
    return 0


# ------------------------------------------------------------------ eval
def cmd_eval(args) -> int:
    from .eval import metrics
    if args.action == "report":
        labels = metrics.load_labels(args.labels)
        res = [metrics.evaluate_run(metrics.load_run(r), labels=labels) for r in args.runs]
        _print(res[0] if len(res) == 1 else {"runs": res, "aggregate": metrics.aggregate_runs(res)})
    elif args.action == "calibrate":
        pts = []
        correct = {}
        if args.correct:
            import csv
            with open(args.correct) as fh:
                correct = {r["finding_id"]: r["correct"] in ("1", "true", "True") for r in csv.DictReader(fh)}
        for r in args.runs:
            for o in metrics.load_run(r)["outcomes"]:
                c = (o.get("decision") or {}).get("confidence")
                if not c:
                    continue
                fid = o["finding"]["finding_id"]
                v = o.get("verifier") or {}
                ok = correct.get(fid) if fid in correct else bool(
                    v and v["L2"]["passed"] and v["L3"]["passed"] and o["rollback"]["L_RB"]["passed"])
                pts.append((c["C"], ok))
        res = metrics.calibrate_thresholds(pts)
        if not args.correct:
            res["warning"] = "no --correct labels: correctness proxied by L2&L3&L_RB (biased; use DBA labels)"
        _print(res)
    elif args.action == "ablation":
        from .eval.ablation import run_ablation
        _print(run_ablation(args.config, args.findings, args.out, args.topology))
    return 0


def cmd_version(_args) -> int:
    print(__version__)
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="orarem", description="ORACLE-REMEDIATE command line")
    p.add_argument("--config", action="append", default=None,
                   help="YAML config; repeat to layer overlays (e.g. local.yaml + a topology profile)")
    sub = p.add_subparsers(dest="cmd", required=True)

    a = sub.add_parser("audit", help="run the catalog invariants and write findings.csv")
    a.add_argument("--out", default="findings.csv")
    a.add_argument("--containers", help="comma-separated PDB names (default: all open)")
    a.add_argument("--from-spool", help="convert a SQL*Plus spool from audit/run_audit.sh")
    a.add_argument("--container", help="container name for --from-spool")
    a.add_argument("--topology", choices=["single", "rac2", "exadata"])
    a.set_defaults(fn=cmd_audit)

    r = sub.add_parser("remediate", help="generate, verify and score remediations for findings")
    r.add_argument("--findings", required=True)
    r.add_argument("--mapping", help="YAML column mapping for third-party finding exports")
    r.add_argument("--only", help="comma-separated control ids")
    r.add_argument("--out", default=None)
    r.add_argument("--eval", action="store_true", help="draw n samples and verify all (Pass@k)")
    r.add_argument("--apply", action="store_true", help="execute AUTO-APPLY (also needs apply.enabled: true)")
    r.add_argument("--topology", choices=["single", "rac2", "exadata"])
    r.set_defaults(fn=cmd_remediate)

    d = sub.add_parser("demo", help="offline end-to-end run on the simulator with the mock LLM")
    d.add_argument("--topology", default="single", choices=["single", "rac2", "exadata"])
    d.add_argument("--out", default="runs")
    d.add_argument("--eval", action="store_true")
    d.add_argument("--no-noise", action="store_true", help="disable mock sampling noise")
    d.set_defaults(fn=cmd_demo)

    c = sub.add_parser("catalog", help="inspect the control catalog")
    c.add_argument("action", choices=["validate", "list", "show", "export-sql"])
    c.add_argument("id", nargs="?")
    c.add_argument("--out")
    c.set_defaults(fn=cmd_catalog)

    g = sub.add_parser("rag", help="documentation store")
    g.add_argument("action", choices=["ingest", "query"])
    g.add_argument("path", nargs="?", default="knowledge")
    g.add_argument("--control")
    g.add_argument("--observed")
    g.set_defaults(fn=cmd_rag)

    e = sub.add_parser("eval", help="evaluation (Pass@k, safety, rollback fidelity, calibration, ablation)")
    e.add_argument("action", choices=["report", "calibrate", "ablation"])
    e.add_argument("runs", nargs="*", help="run directories or run.json files")
    e.add_argument("--labels", help="CSV finding_id,sample_index,unsafe (independent DBA labels)")
    e.add_argument("--correct", help="CSV finding_id,correct (held-out correctness labels)")
    e.add_argument("--findings", help="findings file for ablation")
    e.add_argument("--out", default="runs/ablation")
    e.add_argument("--topology", default=None, choices=["single", "rac2", "exadata"])
    e.set_defaults(fn=cmd_eval)

    v = sub.add_parser("version")
    v.set_defaults(fn=cmd_version)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return int(args.fn(args) or 0)


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
