"""Deterministic, rule-based stand-in for an LLM (tests, CI, offline demo).

It reads the same structured request a real backend receives and answers in the
same JSON schema.  When a context class is present it uses it the way a good
model should (e.g. granting a direct EXECUTE to a dependent schema before
revoking from PUBLIC); when the class is ablated it falls back to what can be
inferred from the finding alone.  Seeded noise produces formatting variants,
wrong candidates and unsafe candidates so that self-consistency agreement,
Layer 1 and pass@k behave non-trivially.

The mock exists to exercise the framework; it says nothing about how a real
model performs.  Report evaluation numbers only from real backends.
"""

from __future__ import annotations

import json
import random
import re
from typing import Any

from ..controls import Control
from ..models import Finding
from .backends import LLMBackend, LLMResponse
from .prompt import GenerationRequest

CIS_PROFILE_LIMITS = {
    "FAILED_LOGIN_ATTEMPTS": "5", "PASSWORD_LOCK_TIME": "1", "PASSWORD_LIFE_TIME": "90",
    "PASSWORD_REUSE_MAX": "20", "PASSWORD_REUSE_TIME": "365", "PASSWORD_GRACE_TIME": "5",
    "PASSWORD_VERIFY_FUNCTION": "ORA12C_STRONG_VERIFY_FUNCTION", "SESSIONS_PER_USER": "10",
    "INACTIVE_ACCOUNT_TIME": "120",
}


def _rows(observed: str) -> list[list[str]]:
    rows = []
    for part in (observed or "").split(";"):
        part = part.strip()
        if part and not part.startswith("(+"):
            rows.append([c.strip() for c in part.split("|")])
    return rows


def _sql_value(v: str | None) -> str:
    if v is None or v == "":
        return "''"
    if re.fullmatch(r"[A-Za-z0-9_]+", v):
        return v.upper()
    return "'" + v.replace("'", "''") + "'"


def reference_remediation(control: Control, finding: Finding, ctx: dict[str, Any],
                          context_aware: bool = True) -> dict[str, Any]:
    k, p = control.kind, control.params
    dep = ctx.get("dependency") if context_aware else None
    topo = ctx.get("topology") if context_aware else None
    dep = dep if isinstance(dep, dict) and "error" not in dep else None
    topo = topo if isinstance(topo, dict) and "error" not in topo else None
    risk, assumptions = "low", []
    rem: list[str] = []
    rb: list[str] = []

    if k == "parameter":
        name = p["name"].lower()
        pc = (dep or {}).get("parameter", {})
        static = str(pc.get("issys_modifiable", "")).upper() == "FALSE" or (not pc and control.requires_restart)
        scope = "SPFILE" if static else "BOTH"
        sid = " SID='*'" if (topo or {}).get("is_rac") else ""
        cur = (pc.get("current_value_by_instance") or {}).get(1) if pc else None
        if not pc:
            obs = _rows(finding.observed_value)
            cur = obs[0][2] if obs and len(obs[0]) > 2 and obs[0][2] != "" else None
        new = "" if p.get("op") == "empty" else str(p["expected"])
        rem.append(f"ALTER SYSTEM SET {name} = {_sql_value(new)} SCOPE={scope}{sid}")
        rb.append(f"ALTER SYSTEM SET {name} = {_sql_value(cur)} SCOPE={scope}{sid}")
        if static:
            assumptions.append("static parameter: takes effect after a rolling instance restart")
            risk = "medium"
        if topo and name == "remote_listener" and topo.get("is_rac"):
            risk = "high"
            assumptions.append("RAC registers with the SCAN listener through REMOTE_LISTENER; clearing it breaks "
                               "service registration -- request a policy exception instead")
        if topo and name == "remote_login_passwordfile" and topo.get("dataguard"):
            risk = "high"
            assumptions.append("Data Guard redo transport authenticates with the password file; NONE breaks it")

    elif k == "profile_limit":
        res = p["resource"].upper()
        target = CIS_PROFILE_LIMITS.get(res, str(p.get("value")))
        if dep and "profiles" in dep:
            for prof in dep["profiles"]:
                own, eff = prof["limit"], prof["effective"]
                if own == "DEFAULT":
                    continue  # fixed through the DEFAULT profile
                if _violates(eff, p):
                    rem.append(f"ALTER PROFILE {prof['profile']} LIMIT {res} {target}")
                    rb.append(f"ALTER PROFILE {prof['profile']} LIMIT {res} {own}")
        else:  # no dependency context: only the effective values from the finding are known
            for row in _rows(finding.observed_value):
                if len(row) >= 3:
                    rem.append(f"ALTER PROFILE {row[0]} LIMIT {res} {target}")
                    rb.append(f"ALTER PROFILE {row[0]} LIMIT {res} {row[2]}")
        if res in ("SESSIONS_PER_USER", "PASSWORD_LIFE_TIME"):
            risk = "medium"
            assumptions.append("pooled/service accounts sharing the profile may be affected")

    elif k == "public_execute":
        obj = p["object"].upper()
        if dep:
            for d in dep.get("dependent_objects", []):
                if not d.get("has_direct_grant") and f"GRANT EXECUTE ON SYS.{obj} TO {d['owner']}" not in rem:
                    rem.append(f"GRANT EXECUTE ON SYS.{obj} TO {d['owner']}")
                    rb.insert(0, f"REVOKE EXECUTE ON SYS.{obj} FROM {d['owner']}")
                    risk = "medium"
                    assumptions.append(f"{d['owner']}.{d['name']} relies on the PUBLIC grant; direct grant preserves it")
        rem.append(f"REVOKE EXECUTE ON SYS.{obj} FROM PUBLIC")
        rb.insert(0, f"GRANT EXECUTE ON SYS.{obj} TO PUBLIC")

    elif k in ("sys_priv", "role_grant", "object_access", "admin_option"):
        svc = set((ctx.get("policy") or {}).get("service_accounts", [])) if context_aware else set()
        for row in _rows(finding.observed_value):
            g = row[0]
            if g in svc:
                risk = "high"
                assumptions.append(f"{g} is a whitelisted service account; confirm with the application owner")
            if k == "role_grant":
                rem.append(f"REVOKE {row[1]} FROM {g}")
                rb.append(f"GRANT {row[1]} TO {g}" + (" WITH ADMIN OPTION" if row[2] == "YES" else ""))
            elif k == "sys_priv":
                rem.append(f"REVOKE {row[1]} FROM {g}")
                rb.append(f"GRANT {row[1]} TO {g}" + (" WITH ADMIN OPTION" if len(row) > 2 and row[2] == "YES" else ""))
            elif k == "object_access":
                rem.append(f"REVOKE {row[3]} ON {row[1]}.{row[2]} FROM {g}")
                rb.append(f"GRANT {row[3]} ON {row[1]}.{row[2]} TO {g}")
            else:  # admin_option: re-grant without admin option
                rem += [f"REVOKE {row[1]} FROM {g}", f"GRANT {row[1]} TO {g}"]
                rb += [f"REVOKE {row[1]} FROM {g}", f"GRANT {row[1]} TO {g} WITH ADMIN OPTION"]
        if control.id == "ch6.no_dba_role":
            risk = "high"

    elif k == "no_public_db_links":
        links = (dep or {}).get("public_links") or [
            {"db_link": r[1], "host": r[2] if len(r) > 2 else "", "username": "UNKNOWN"} for r in
            _rows(finding.observed_value)]
        for lk in links:
            rem.append(f"DROP PUBLIC DATABASE LINK {lk['db_link']}")
            rb.append(f"CREATE PUBLIC DATABASE LINK {lk['db_link']} CONNECT TO {lk.get('username') or 'UNKNOWN'} "
                      f"IDENTIFIED BY \"PLACEHOLDER_CHANGE_ME\" USING '{lk.get('host', '')}'")
        risk = "high"
        assumptions.append("original link credentials are not recoverable; rollback uses a placeholder password")
        if dep and dep.get("dependent_objects"):
            assumptions.append(f"{len(dep['dependent_objects'])} dependent objects reference the link(s)")

    elif k == "users_default_profile":
        users = (dep or {}).get("users") or [r[0] for r in _rows(finding.observed_value)]
        prof = "ORAREM_APP_PROFILE"
        limits = CIS_PROFILE_LIMITS if context_aware else {"FAILED_LOGIN_ATTEMPTS": "5"}
        rem.append(f"CREATE PROFILE {prof} LIMIT " + " ".join(f"{r} {v}" for r, v in limits.items()))
        for u in users:
            rem.append(f"ALTER USER {u} PROFILE {prof}")
            rb.append(f"ALTER USER {u} PROFILE DEFAULT")
        rb.append(f"DROP PROFILE {prof}")
        risk = "medium"

    elif k == "audit_action":
        opt = p["option"].upper()
        pol = "ORAREM_AUD_" + re.sub(r"[^A-Z0-9]+", "_", opt)
        rem += [f"CREATE AUDIT POLICY {pol} ACTIONS {opt}", f"AUDIT POLICY {pol}"]
        rb += [f"NOAUDIT POLICY {pol}", f"DROP AUDIT POLICY {pol}"]
        risk = "medium"
        assumptions.append("adds unified audit records to AUDSYS; monitor tablespace growth")

    elif k == "ora_file":
        f = p["file"].lower()
        key = p.get("key", "").replace("{listener}", "LISTENER")
        entries = (dep or {}).get("file_entries") or {}
        cur = entries.get(key.upper()) if dep else next((r[1] for r in _rows(finding.observed_value)
                                                         if r and r[0] == key.upper() and len(r) > 1 and r[1]), None)
        val = "(TCPS,IPC)" if p.get("op") == "present" else str(p.get("expected"))
        rem.append(f"ORA_SET {f} {key} = {val}")
        rb.append(f"ORA_SET {f} {key} = {cur}" if cur else f"ORA_UNSET {f} {key}")
        risk = "medium" if "SQLNET" in key else "low"
        if "SQLNET" in key:
            assumptions.append("all clients must support native network encryption/integrity before REQUIRED")

    else:
        rem.append("-- no automated remediation for this control kind")
        risk = "high"

    return {
        "remediation_sql": ";\n".join(rem) + (";" if rem else ""),
        "rollback_sql": ";\n".join(rb) + (";" if rb else ""),
        "verification_sql": control.invariant() or "-- file-based: re-run orarem audit",
        "prerequisites": ["shadow PDB / sandbox verification passed", "change ticket approved"],
        "risk_level": risk,
        "assumptions": assumptions,
        "rationale": f"Bring {control.id} into compliance ({finding.expected_value}).",
    }


def _mutate_wrong(sql: str) -> str:
    """Plausible but incorrect candidate (incomplete or wrong target/value)."""
    stmts = [s for s in sql.split(";\n") if s.strip()]
    if len(stmts) > 1:
        return ";\n".join(stmts[:-1]).rstrip(";") + ";"
    s = stmts[0] if stmts else sql
    if "FROM PUBLIC" in s:
        return s.replace("FROM PUBLIC", "FROM SCOTT")
    if s.startswith("ALTER SYSTEM SET"):
        return re.sub(r"=\s*\S+", "= 'WRONG_VALUE'", s, count=1)
    if s.startswith("ORA_SET"):
        return re.sub(r"=\s*.*$", "= ACCEPTED", s.rstrip(";"))
    return s.replace("REVOKE", "REVOKE SELECT ANY TABLE,", 1) if s.startswith("REVOKE") else s


def _violates(eff: str, p: dict[str, Any]) -> bool:
    op = p.get("op", "le")
    try:
        n = float(eff)
    except (TypeError, ValueError):
        n = None
    if op == "le":
        return eff == "UNLIMITED" or n is None or n > float(p["value"])
    if op == "ge":
        return eff != "UNLIMITED" and (n is None or n < float(p["value"]))
    return eff in ("NULL", "DEFAULT", "UNLIMITED", "", None)


class MockRemediationBackend(LLMBackend):
    name = "mock"

    def __init__(self, model: str = "mock-remediator", seed: int = 7, p_variant: float = 0.15,
                 p_wrong: float = 0.10, p_unsafe: float = 0.05, context_aware: bool = True, **kw):
        super().__init__(model, **kw)
        self.seed = seed
        self.p_variant, self.p_wrong, self.p_unsafe = p_variant, p_wrong, p_unsafe
        self.context_aware = context_aware

    def _send_temperature(self) -> bool:
        return self.temperature is not None and self.temperature_policy != "never"

    def _call(self, request: GenerationRequest, send_temperature: bool, sample_index: int, seed: int) -> LLMResponse:
        rng = random.Random(f"{self.seed}:{seed}:{request.finding.finding_id}:{sample_index}")
        out = reference_remediation(request.control, request.finding, request.context, self.context_aware)
        temp = self.temperature if send_temperature else 1.0
        scale = max(0.0, min(2.0, (temp or 0.0) / 0.3)) if temp else 0.0
        roll = rng.random()
        if roll < self.p_unsafe * scale:
            out["remediation_sql"] = "DROP USER SCOTT CASCADE;\n" + out["remediation_sql"]
        elif roll < (self.p_unsafe + self.p_wrong) * scale:
            out["remediation_sql"] = _mutate_wrong(out["remediation_sql"])
        elif roll < (self.p_unsafe + self.p_wrong + self.p_variant) * scale:
            # formatting-only variant: identical after canonicalisation
            out["remediation_sql"] = "-- generated remediation\n" + out["remediation_sql"].replace(";\n", " ;\n\n  ")
        text = json.dumps(out, indent=1)
        return LLMResponse(text, input_tokens=len(request.system + request.user) // 4,
                           output_tokens=len(text) // 4, temperature_applied=temp if send_temperature else None)
