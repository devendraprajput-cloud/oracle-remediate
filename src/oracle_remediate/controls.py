"""Control catalog and machine-checkable invariants phi_c (paper Section III.E-2).

Each control is declared *typed* in ``controls/catalog.yaml`` (``kind`` +
``params``).  From that single declaration the framework derives:

* the Oracle SQL invariant ``phi_c(D)`` -- returns rows iff the control is
  NON-compliant (empty result set == compliant);
* the same predicate evaluated in Python by the offline simulator;
* the statement-type whitelist used by Layer 1 (via ``control_class``).

Keeping one source of truth avoids the audit SQL and the verifier drifting
apart.  ``kind: custom`` accepts a raw ``invariant_sql`` for controls that do
not fit a template.

IMPORTANT: the catalog shipped with this repository is a *reference subset*.
CIS benchmark text is licensed by the Center for Internet Security and is not
reproduced here; every control carries a ``provenance`` field and ``cis_id`` is
filled only where the paper itself states the identifier.  Map the remaining
identifiers from your licensed CIS Oracle Database 19c v2.0.0 PDF and extend
the catalog (see docs/CONTROL_CATALOG.md).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

# Control classes (Section III.E-1, Listing 1) ------------------------------------------
CONTROL_CLASSES = {
    "ch1_patch": "Installation and patching",
    "ch2_param": "Database initialisation parameters",
    "ch2_file": "Listener / SQLNET configuration files",
    "ch3_prof": "Connection and login restrictions (profiles)",
    "ch4_user": "Users",
    "ch5_audit": "Unified audit policies",
    "ch6_priv": "Privileges and grants",
}

SUPPORTED_KINDS = {
    "parameter", "ora_file", "profile_limit", "public_execute", "sys_priv", "role_grant",
    "admin_option", "object_access", "no_public_db_links", "users_default_profile",
    "default_passwords", "external_auth", "audit_action", "manual", "custom",
}

_IDENT = re.compile(r"^[A-Za-z][A-Za-z0-9_$# ]{0,127}$")


def sql_literal(value: str) -> str:
    """Quote a catalog value as an Oracle string literal (catalog is trusted, still escaped)."""
    return "'" + str(value).replace("'", "''") + "'"


def _in_list(values: list[str]) -> str:
    return ", ".join(sql_literal(v.upper()) for v in values)


NON_MAINTAINED_GRANTEE = (
    "grantee NOT IN (SELECT username FROM dba_users WHERE oracle_maintained = 'Y')\n"
    "   AND grantee NOT IN (SELECT role FROM dba_roles WHERE oracle_maintained = 'Y')"
)


@dataclass
class Control:
    id: str
    title: str
    control_class: str
    kind: str
    params: dict[str, Any] = field(default_factory=dict)
    cis_id: str | None = None
    provenance: str = "cis-19c-family"
    chapter: int | None = None
    scope: str = "auto"  # auto | pdb | cdb | file
    rollback_possible: bool = True
    review_only: bool = False
    requires_restart: bool = False
    expected_tables_extra: list[str] = field(default_factory=list)
    invariant_sql: str | None = None
    notes: str = ""
    keywords: list[str] = field(default_factory=list)

    # ------------------------------------------------------------------ derived
    @property
    def in_automated_scope(self) -> bool:
        """Controls without an invertible rollback are routed to manual review (III.F)."""
        return self.rollback_possible and self.kind not in ("manual",)

    @property
    def is_file_control(self) -> bool:
        return self.kind == "ora_file"

    def invariant(self) -> str | None:
        """Return the Oracle SQL predicate phi_c, or None if not SQL-checkable."""
        if self.invariant_sql:
            return self.invariant_sql.strip()
        return build_invariant_sql(self)


def build_invariant_sql(c: Control) -> str | None:
    p = c.params
    k = c.kind
    if k == "parameter":
        name = p["name"].lower()
        op = p.get("op", "eq")
        base = f"SELECT inst_id, name, value\n  FROM gv$parameter\n WHERE name = {sql_literal(name)}"
        if op == "eq":
            exp = re.sub(r"\s+", "", str(p["expected"])).upper()
            return base + f"\n   AND UPPER(REPLACE(NVL(value, '#NULL#'), ' ', '')) <> {sql_literal(exp)}"
        if op == "empty":
            return base + "\n   AND value IS NOT NULL"
        if op in ("le", "ge"):
            cmp = ">" if op == "le" else "<"
            n = float(p["expected"])
            return (base + "\n   AND (value IS NULL\n        OR TO_NUMBER(value DEFAULT NULL ON CONVERSION ERROR) IS NULL"
                    f"\n        OR TO_NUMBER(value DEFAULT NULL ON CONVERSION ERROR) {cmp} {n:g})")
        raise ValueError(f"{c.id}: unsupported parameter op {op}")
    if k == "profile_limit":
        res = p["resource"].upper()
        op = p.get("op", "le")
        num = "TO_NUMBER(eff DEFAULT NULL ON CONVERSION ERROR)"
        if op == "le":
            cond = f"eff = 'UNLIMITED' OR {num} IS NULL OR {num} > {float(p['value']):g}"
        elif op == "ge":
            # UNLIMITED is treated as compliant for lower bounds (stricter than any number);
            # see docs/CONTROL_CATALOG.md for the PASSWORD_REUSE_* interaction caveat.
            cond = f"eff <> 'UNLIMITED' AND ({num} IS NULL OR {num} < {float(p['value']):g})"
        elif op == "not_null":
            cond = "eff IS NULL OR eff IN ('NULL', 'DEFAULT', 'UNLIMITED')"
        else:
            raise ValueError(f"{c.id}: unsupported profile op {op}")
        return (
            "WITH d AS (SELECT resource_name, limit FROM dba_profiles WHERE profile = 'DEFAULT'),\n"
            "     p AS (SELECT p.profile, p.resource_name,\n"
            "                  CASE WHEN p.limit = 'DEFAULT' THEN d.limit ELSE p.limit END AS eff\n"
            "             FROM dba_profiles p JOIN d ON d.resource_name = p.resource_name\n"
            f"            WHERE p.resource_name = {sql_literal(res)})\n"
            f"SELECT profile, resource_name, eff FROM p\n WHERE {cond}"
        )
    if k == "public_execute":
        return (
            "SELECT grantee, owner, table_name, privilege\n  FROM dba_tab_privs\n"
            f" WHERE grantee = 'PUBLIC' AND privilege = 'EXECUTE'\n   AND owner = {sql_literal(p.get('owner', 'SYS'))}"
            f" AND table_name = {sql_literal(p['object'].upper())}"
        )
    if k == "sys_priv":
        if "pattern" in p:
            pred = f"privilege LIKE {sql_literal(p['pattern'])}"
        else:
            pred = f"privilege IN ({_in_list(p['privileges'])})"
        return f"SELECT grantee, privilege, admin_option\n  FROM dba_sys_privs\n WHERE {pred}\n   AND {NON_MAINTAINED_GRANTEE}"
    if k == "role_grant":
        return (f"SELECT grantee, granted_role, admin_option\n  FROM dba_role_privs\n"
                f" WHERE granted_role IN ({_in_list(p['roles'])})\n   AND {NON_MAINTAINED_GRANTEE}")
    if k == "admin_option":
        return f"SELECT grantee, privilege\n  FROM dba_sys_privs\n WHERE admin_option = 'YES'\n   AND {NON_MAINTAINED_GRANTEE}"
    if k == "object_access":
        return (f"SELECT grantee, owner, table_name, privilege\n  FROM dba_tab_privs\n"
                f" WHERE owner = {sql_literal(p.get('owner', 'SYS'))} AND table_name IN ({_in_list(p['objects'])})"
                f"\n   AND {NON_MAINTAINED_GRANTEE}")
    if k == "no_public_db_links":
        return "SELECT owner, db_link, host\n  FROM dba_db_links\n WHERE owner = 'PUBLIC'"
    if k == "users_default_profile":
        return "SELECT username, profile\n  FROM dba_users\n WHERE profile = 'DEFAULT' AND oracle_maintained = 'N'"
    if k == "default_passwords":
        return ("SELECT d.username\n  FROM dba_users_with_defpwd d\n  JOIN dba_users u ON u.username = d.username\n"
                " WHERE u.account_status = 'OPEN'")
    if k == "external_auth":
        return ("SELECT username, authentication_type\n  FROM dba_users\n"
                " WHERE authentication_type = 'EXTERNAL' AND oracle_maintained = 'N'")
    if k == "audit_action":
        opt = p["option"].upper()
        typ = p.get("option_type", "STANDARD ACTION")
        return (
            f"SELECT {sql_literal(opt)} AS missing_audit_option FROM dual\n WHERE NOT EXISTS (\n"
            "   SELECT 1\n     FROM audit_unified_policies p\n"
            "     JOIN audit_unified_enabled_policies e ON e.policy_name = p.policy_name\n"
            f"    WHERE p.audit_option = {sql_literal(opt)}\n      AND p.audit_option_type = {sql_literal(typ)}\n"
            "      AND NVL(p.audit_condition, 'NONE') = 'NONE'\n"
            "      AND e.success = 'YES' AND e.failure = 'YES'\n"
            "      AND e.enabled_option = 'BY USER' AND e.entity_name = 'ALL USERS')"
        )
    if k in ("ora_file", "manual"):
        return None
    if k == "custom":
        return c.invariant_sql
    raise ValueError(f"{c.id}: unknown kind {k}")


class Catalog:
    """Loaded control catalog with lookup helpers."""

    def __init__(self, controls: list[Control], meta: dict[str, Any] | None = None):
        self.controls = controls
        self.meta = meta or {}
        self._by_id = {c.id: c for c in controls}
        self._by_cis = {c.cis_id: c for c in controls if c.cis_id}

    def __len__(self) -> int:
        return len(self.controls)

    def __iter__(self):
        return iter(self.controls)

    def get(self, control_id: str) -> Control | None:
        return self._by_id.get(control_id) or self._by_cis.get(control_id)

    @classmethod
    def load(cls, path: str | Path) -> Catalog:
        data = yaml.safe_load(Path(path).read_text())
        controls = []
        for raw in data["controls"]:
            c = Control(**raw)
            validate_control(c)
            controls.append(c)
        ids = [c.id for c in controls]
        dup = {i for i in ids if ids.count(i) > 1}
        if dup:
            raise ValueError(f"duplicate control ids: {sorted(dup)}")
        return cls(controls, data.get("meta", {}))

    def completeness(self) -> dict[str, Any]:
        target = int(self.meta.get("target_controls", 92))
        by_class: dict[str, int] = {}
        for c in self.controls:
            by_class[c.control_class] = by_class.get(c.control_class, 0) + 1
        return {
            "controls_in_catalog": len(self.controls),
            "paper_target": target,
            "missing_vs_target": max(0, target - len(self.controls)),
            "with_cis_id": sum(1 for c in self.controls if c.cis_id),
            "in_automated_scope": sum(1 for c in self.controls if c.in_automated_scope),
            "by_class": dict(sorted(by_class.items())),
            "by_provenance": _count(self.controls, "provenance"),
        }


def _count(items: list[Control], attr: str) -> dict[str, int]:
    out: dict[str, int] = {}
    for c in items:
        out[getattr(c, attr)] = out.get(getattr(c, attr), 0) + 1
    return out


def validate_control(c: Control) -> None:
    if c.control_class not in CONTROL_CLASSES:
        raise ValueError(f"{c.id}: unknown control_class {c.control_class}")
    if c.kind not in SUPPORTED_KINDS:
        raise ValueError(f"{c.id}: unknown kind {c.kind}")
    if c.kind == "custom" and not c.invariant_sql:
        raise ValueError(f"{c.id}: kind custom requires invariant_sql")
    for v in c.params.get("roles", []) + c.params.get("objects", []) + c.params.get("privileges", []):
        if not _IDENT.match(str(v)):
            raise ValueError(f"{c.id}: suspicious identifier {v!r}")
    # Build once so malformed params fail at load time, not mid-run.
    build_invariant_sql(c)
