"""Audit phase (Fig. 1, step 1): run the catalog's invariants and emit findings.

Targets:
  * :class:`OracleAuditTarget` -- python-oracledb, iterates open containers with
    ``ALTER SESSION SET CONTAINER`` (requires a common user with SET CONTAINER)
  * :class:`SimulatedAuditTarget` -- the offline simulator

File-based controls read listener.ora / sqlnet.ora from the paths in the
configuration (run the audit on the database host, or copy the files).
``audit/run_audit.sh`` provides the Bash + SQL*Plus route named in Table II.
"""

from __future__ import annotations

from pathlib import Path
from typing import Protocol

from ..controls import Catalog, Control
from ..models import Finding
from ..verify import orafile


class AuditTarget(Protocol):
    def containers(self) -> list[str]: ...

    def evaluate(self, control: Control, container: str) -> frozenset | None: ...


def _summarise(rows: frozenset, limit: int = 6) -> str:
    rs = sorted(rows, key=str)
    s = "; ".join("|".join("" if v is None else str(v) for v in (r if isinstance(r, tuple) else (r,))) for r in rs[:limit])
    return s + (f"; (+{len(rs) - limit} more)" if len(rs) > limit else "")


def _expected(c: Control) -> str:
    p = c.params
    if c.kind in ("parameter", "ora_file"):
        op = p.get("op", "eq")
        return {"eq": f"= {p.get('expected')}", "le": f"<= {p.get('expected')}", "ge": f">= {p.get('expected')}",
                "empty": "empty", "present": "present", "absent_substring": f"no {p.get('substring')}"}.get(op, op)
    if c.kind == "profile_limit":
        return {"le": f"<= {p.get('value')}", "ge": f">= {p.get('value')}", "not_null": "set"}[p.get("op", "le")]
    return "no rows"


def _grantees(c: Control, rows: frozenset) -> list[str]:
    if c.kind in ("sys_priv", "role_grant", "admin_option", "object_access", "public_execute",
                  "users_default_profile", "default_passwords", "external_auth"):
        return sorted({str(r[0]) for r in rows if isinstance(r, tuple) and r})
    if c.kind == "profile_limit":
        return sorted({str(r[0]) for r in rows})
    return []


def run_audit(catalog: Catalog, target: AuditTarget, containers: list[str] | None = None,
              include_manual: bool = True) -> list[Finding]:
    findings: list[Finding] = []
    for cont in containers or target.containers():
        for c in catalog:
            if c.kind == "manual":
                if include_manual and cont == (containers or target.containers())[0]:
                    findings.append(Finding(c.id, c.title, "manual review required", "see benchmark",
                                            [cont], [], "", c.cis_id))
                continue
            if c.is_file_control and cont != (containers or target.containers())[0]:
                continue  # host-level files are audited once
            rows = target.evaluate(c, cont)
            if not rows:
                continue
            findings.append(Finding(
                control_id=c.id, title=c.title, observed_value=_summarise(rows), expected_value=_expected(c),
                affected_containers=[cont] if not c.is_file_control else ["HOST"],
                affected_grantees=_grantees(c, rows), raw_audit_sql=c.invariant() or "", cis_id=c.cis_id))
    return findings


class SimulatedAuditTarget:
    def __init__(self, db, listeners: list[str] | None = None):
        self.db = db
        self.listeners = listeners or ["LISTENER"]

    def containers(self) -> list[str]:
        return [c["name"] for c in self.db.s.topology["containers"] if c["name"] not in ("PDB$SEED", "CDB$ROOT")]

    def evaluate(self, control: Control, container: str) -> frozenset | None:
        return self.db.evaluate(control, self.listeners)


class OracleAuditTarget:
    def __init__(self, client, files: dict[str, str | None], listeners: list[str], only: list[str] | None = None):
        self.client = client
        self.files = files
        self.listeners = listeners
        self.only = only or []

    def containers(self) -> list[str]:
        rows = self.client.query("SELECT name FROM v$containers WHERE open_mode IN ('READ WRITE','READ ONLY') "
                                 "AND name <> 'PDB$SEED' ORDER BY con_id")
        names = [r[0] for r in rows]
        return [n for n in names if not self.only or n in self.only]

    def evaluate(self, control: Control, container: str) -> frozenset | None:
        if control.is_file_control:
            path = self.files.get(control.params.get("file", "").replace(".", "_"))
            text = Path(path).read_text() if path and Path(path).exists() else ""
            return frozenset(orafile.evaluate(text, control.params, self.listeners))
        sql = control.invariant()
        if not sql:
            return None
        self.client.set_container(container)
        return frozenset(tuple(r) for r in self.client.query(sql))
