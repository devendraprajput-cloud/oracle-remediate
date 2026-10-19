"""Finding Ingestion Layer (paper Section III.A).

Normalises findings from any CIS-19c audit tool into :class:`Finding`.
Supported inputs:

* ``findings.csv`` produced by ``orarem audit`` / ``audit/run_audit.sh``
  (columns below; list fields are ``;``-separated)
* JSON Lines with the same field names
* any other assessor via a YAML column mapping (``--mapping``), e.g. an
  export of DBSAT or a SCAP/InSpec report flattened to CSV.  The exact column
  names of third-party exports vary by version, so the mapping is supplied by
  the operator rather than hard-coded.
"""

from __future__ import annotations

import csv
import json
from pathlib import Path

import yaml

from ..models import Finding

CSV_FIELDS = ["control_id", "cis_id", "title", "observed_value", "expected_value",
              "affected_containers", "affected_grantees", "raw_audit_sql", "source"]
_LIST_FIELDS = {"affected_containers", "affected_grantees"}


def _row_to_finding(row: dict[str, str]) -> Finding:
    kw = {}
    for f in CSV_FIELDS:
        v = row.get(f)
        if v is None:
            continue
        if f in _LIST_FIELDS:
            kw[f] = [x.strip() for x in (v if isinstance(v, list) else str(v).split(";")) if str(x).strip()]
        else:
            kw[f] = v if v != "" else (None if f == "cis_id" else "")
    if not kw.get("control_id"):
        raise ValueError(f"finding without control_id: {row}")
    return Finding(**kw)


def read_findings(path: str | Path, mapping: str | Path | None = None) -> list[Finding]:
    p = Path(path)
    colmap: dict[str, str] = {}
    if mapping:
        colmap = (yaml.safe_load(Path(mapping).read_text()) or {}).get("columns", {})
    rows: list[dict] = []
    if p.suffix.lower() in (".jsonl", ".ndjson"):
        rows = [json.loads(line) for line in p.read_text().splitlines() if line.strip()]
    elif p.suffix.lower() == ".json":
        data = json.loads(p.read_text())
        rows = data if isinstance(data, list) else data.get("findings", [])
    else:
        with p.open(newline="") as fh:
            rows = list(csv.DictReader(fh))
    if colmap:
        rows = [{ours: r.get(theirs, "") for ours, theirs in colmap.items()} for r in rows]
    return [_row_to_finding(r) for r in rows]


def write_findings(findings: list[Finding], path: str | Path) -> None:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=CSV_FIELDS)
        w.writeheader()
        for f in findings:
            d = f.to_dict()
            for lf in _LIST_FIELDS:
                d[lf] = ";".join(d[lf])
            w.writerow({k: d.get(k) if d.get(k) is not None else "" for k in CSV_FIELDS})
