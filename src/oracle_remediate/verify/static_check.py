"""Layer 1 -- static AST whitelist enforcement (paper Section III.E-1, Listing 1).

The paper's Listing 1 raises on the first violation; the architecture
(Section III.D) states that verifiers are *informational*.  This module
therefore records ``L1 in {0, 1}`` together with every violation found and
never raises.

Checks (paper):
  * statement kind must not be in FORBIDDEN
  * statement kind must be in the whitelist of the finding's control class

Implementation safeguards (documented in docs/DESIGN_NOTES.md):
  * ``ALTER SYSTEM`` must be ``SET``/``RESET`` of the control's own parameter
  * ``ORA_SET``/``ORA_UNSET`` must target the control's own file and key
  * privilege-escalation guard on the remediation script (no ANY / DBA / SYSDBA
    grants, no WITH ADMIN/GRANT OPTION, no grants TO PUBLIC)
  * ``ALTER USER ... IDENTIFIED`` (password change) is non-invertible -> fail
  * rollback is checked against a rollback whitelist, and every GRANT in the
    rollback must restore a privilege the remediation revoked (inverse check)
"""

from __future__ import annotations

from ..controls import Control
from ..models import LayerResult
from .sqltools import Statement, parse_script

# Paper Listing 1 (verbatim sets), extended with the kinds needed for the
# remaining control classes of the reference catalog.
CONTROL_WHITELIST: dict[str, set[str]] = {
    "ch6_priv": {"GRANT", "REVOKE", "ALTER USER", "CREATE ROLE"},
    "ch5_audit": {"CREATE AUDIT POLICY", "AUDIT", "NOAUDIT"},
    "ch3_prof": {"ALTER PROFILE", "CREATE PROFILE"},
    "ch2_param": {"ALTER SYSTEM"},
    # extensions
    "ch4_user": {"ALTER USER", "CREATE PROFILE", "DROP DATABASE LINK", "CREATE DATABASE LINK"},
    "ch2_file": {"ORA_SET", "ORA_UNSET"},
    "ch1_patch": set(),
}

# Rollback scripts legitimately contain inverse statement types.
ROLLBACK_WHITELIST: dict[str, set[str]] = {
    "ch6_priv": {"GRANT", "REVOKE", "ALTER USER", "DROP ROLE"},
    "ch5_audit": {"NOAUDIT", "AUDIT", "DROP AUDIT POLICY", "ALTER AUDIT POLICY"},
    "ch3_prof": {"ALTER PROFILE", "DROP PROFILE"},
    "ch2_param": {"ALTER SYSTEM"},
    "ch4_user": {"ALTER USER", "DROP PROFILE", "CREATE DATABASE LINK", "DROP DATABASE LINK"},
    "ch2_file": {"ORA_SET", "ORA_UNSET"},
    "ch1_patch": set(),
}

# Paper Listing 1 FORBIDDEN, plus statements that are never acceptable in an
# automated remediation (instance/PDB lifecycle, dynamic PL/SQL, host commands).
FORBIDDEN: set[str] = {
    "DROP USER", "DROP TABLE", "TRUNCATE", "SHUTDOWN", "ALTER DATABASE", "DROP TABLESPACE",
    # extensions
    "STARTUP", "ALTER PLUGGABLE DATABASE", "CREATE PLUGGABLE DATABASE", "DROP PLUGGABLE DATABASE",
    "ALTER SYSTEM OTHER", "PLSQL_BLOCK", "HOST", "ALTER TABLESPACE",
}

_ESCALATING_ROLES = {"DBA", "SYSDBA", "SYSOPER", "SYSBACKUP", "SYSDG", "SYSKM", "SYSRAC",
                     "IMP_FULL_DATABASE", "EXP_FULL_DATABASE", "DATAPUMP_IMP_FULL_DATABASE"}


def _priv_key(privs: list[str], obj: str | None, grantee: str) -> list[str]:
    return [f"{p}|{(obj or '').replace('SYS.', '')}|{grantee}" for p in privs]


def _escalation(st: Statement) -> str | None:
    if st.kind != "GRANT":
        return None
    a = st.attrs
    privs = a.get("privileges", [])
    opts = " ".join(a.get("options", []))
    if "PUBLIC" in a.get("grantees", []):
        return "grant to PUBLIC"
    if "ADMIN OPTION" in opts or "GRANT OPTION" in opts:
        return "grant WITH ADMIN/GRANT OPTION"
    for p in privs:
        if " ANY " in f" {p} " or p in _ESCALATING_ROLES or p in ("ALL", "ALL PRIVILEGES"):
            return f"grant of escalating privilege {p}"
    return None


def static_check(remediation_sql: str, rollback_sql: str, control: Control,
                 listeners: list[str] | None = None) -> LayerResult:
    violations: list[str] = []
    rem = parse_script(remediation_sql)
    rb = parse_script(rollback_sql)
    allowed = CONTROL_WHITELIST.get(control.control_class, set())
    allowed_rb = ROLLBACK_WHITELIST.get(control.control_class, set())

    if not rem:
        violations.append("empty remediation")
    if not rb:
        violations.append("empty rollback (no one-way remediation is accepted, paper III.F)")

    for label, stmts, wl in (("remediation", rem, allowed), ("rollback", rb, allowed_rb)):
        for st in stmts:
            if st.kind in FORBIDDEN:
                violations.append(f"{label}: UnsafeStatement({st.kind})")
            elif st.kind not in wl:
                violations.append(f"{label}: OutOfScope({st.kind}, {control.control_class})")
            violations.extend(f"{label}: {v}" for v in _target_checks(st, control, listeners or ["LISTENER"]))

    for st in rem:
        esc = _escalation(st)
        if esc:
            violations.append(f"remediation: privilege-escalation guard ({esc})")

    # Inverse check: rollback GRANTs must restore privileges revoked by the remediation.
    revoked = set()
    for st in rem:
        if st.kind == "REVOKE":
            for g in st.attrs.get("grantees", []):
                revoked.update(_priv_key(st.attrs.get("privileges", []), st.attrs.get("object"), g))
    granted_by_rem = set()
    for st in rem:
        if st.kind == "GRANT":
            for g in st.attrs.get("grantees", []):
                granted_by_rem.update(_priv_key(st.attrs.get("privileges", []), st.attrs.get("object"), g))
    for st in rb:
        if st.kind == "GRANT":
            for g in st.attrs.get("grantees", []):
                for key in _priv_key(st.attrs.get("privileges", []), st.attrs.get("object"), g):
                    if key not in revoked:
                        violations.append(f"rollback: GRANT {key} does not restore a revoked privilege")
        if st.kind == "REVOKE":
            for g in st.attrs.get("grantees", []):
                for key in _priv_key(st.attrs.get("privileges", []), st.attrs.get("object"), g):
                    if key not in granted_by_rem:
                        violations.append(f"rollback: REVOKE {key} does not undo a remediation grant")

    return LayerResult(
        passed=0 if violations else 1,
        detail="ok" if not violations else "; ".join(violations[:8]),
        evidence={
            "remediation_kinds": [s.kind for s in rem],
            "rollback_kinds": [s.kind for s in rb],
            "violations": violations,
        },
    )


def _target_checks(st: Statement, control: Control, listeners: list[str]) -> list[str]:
    out: list[str] = []
    if st.kind == "ALTER SYSTEM" and control.kind == "parameter":
        target = control.params.get("name", "").lower()
        if st.attrs.get("parameter") != target:
            out.append(f"ALTER SYSTEM targets {st.attrs.get('parameter')!r}, control parameter is {target!r}")
    if st.kind == "ALTER USER" and st.attrs.get("changes_password"):
        out.append("ALTER USER ... IDENTIFIED (password change) is non-invertible")
    if st.kind in ("ORA_SET", "ORA_UNSET"):
        a = st.attrs
        if a.get("malformed"):
            out.append(f"malformed {st.kind}")
        else:
            exp_file = control.params.get("file", "").lower()
            key_t = control.params.get("key", "")
            keys = {key_t.replace("{listener}", ln.upper()).upper() for ln in listeners} if key_t else set()
            if a["file"] != exp_file:
                out.append(f"{st.kind} targets file {a['file']!r}, control file is {exp_file!r}")
            if keys and a["key"] not in keys:
                out.append(f"{st.kind} targets key {a['key']!r}, allowed {sorted(keys)}")
    return out
