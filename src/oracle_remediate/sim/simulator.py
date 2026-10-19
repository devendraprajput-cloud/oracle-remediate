"""Offline simulator of the Oracle dictionary state touched by CIS remediations.

Purpose: unit tests, CI, the ``orarem demo`` command and framework development
without a licensed Oracle database.  It models exactly the views that the
verifier snapshots (privileges, profiles, parameters, unified audit, database
links and object validity) and executes the statement types in the Layer-1
whitelists.  Behaviour that matters for the paper's examples is modelled:

* revoking EXECUTE from PUBLIC invalidates definer-rights code whose owner has
  no direct grant (roles do not count for definer-rights PL/SQL);
* dropping a database link invalidates dependent views, and a recreated link
  cannot restore the original credentials (paper Section III.G);
* static parameters reject ``SCOPE=MEMORY|BOTH`` (ORA-02095).

It is NOT a substitute for the shadow-PDB verification against a real
Oracle database; error codes and edge cases are approximations.
"""

from __future__ import annotations

import copy
import hashlib
from dataclasses import dataclass, field
from typing import Any

from ..controls import Control
from ..verify import orafile
from ..verify.bisimulation import Snapshot
from ..verify.sandbox import ExecResult, Sandbox
from ..verify.sqltools import Statement, Token

PROFILE_RESOURCES = [
    "COMPOSITE_LIMIT", "SESSIONS_PER_USER", "CPU_PER_SESSION", "CPU_PER_CALL", "LOGICAL_READS_PER_SESSION",
    "LOGICAL_READS_PER_CALL", "IDLE_TIME", "CONNECT_TIME", "PRIVATE_SGA", "FAILED_LOGIN_ATTEMPTS",
    "PASSWORD_LIFE_TIME", "PASSWORD_REUSE_TIME", "PASSWORD_REUSE_MAX", "PASSWORD_VERIFY_FUNCTION",
    "PASSWORD_LOCK_TIME", "PASSWORD_GRACE_TIME", "INACTIVE_ACCOUNT_TIME",
]
PASSWORD_RESOURCES = {r for r in PROFILE_RESOURCES if r.startswith("PASSWORD") or r in
                      ("FAILED_LOGIN_ATTEMPTS", "INACTIVE_ACCOUNT_TIME")}


class SimError(Exception):
    pass


@dataclass
class SimState:
    topology: dict[str, Any]
    parameters: dict[str, str | None]
    param_meta: dict[str, dict[str, bool]]
    spparameters: dict[str, str]
    profiles: dict[str, dict[str, str]]
    users: dict[str, dict[str, Any]]
    roles: dict[str, dict[str, Any]]
    sys_privs: set[tuple[str, str, str]]  # grantee, privilege, admin_option
    tab_privs: set[tuple[str, str, str, str, str]]  # grantee, owner, object, privilege, grantable
    role_privs: set[tuple[str, str, str]]  # grantee, role, admin_option
    audit_policies: dict[str, list[tuple[str, str]]]  # policy -> [(option, option_type)]
    enabled_policies: dict[str, tuple[str, str, str, str]]  # policy -> (enabled_option, entity, success, failure)
    db_links: dict[tuple[str, str], dict[str, str]]
    objects: dict[tuple[str, str, str], str]  # (owner, name, type) -> status
    dependencies: list[dict[str, str]]
    files: dict[str, str] = field(default_factory=dict)  # sqlnet.ora / listener.ora text


class SimulatedOracle:
    """Mutable simulated database. ``clone()`` returns an independent shadow copy."""

    def __init__(self, state: SimState):
        self.s = state

    def clone(self) -> SimulatedOracle:
        return SimulatedOracle(copy.deepcopy(self.s))

    # ================================================================== helpers
    def _oracle_maintained(self, name: str) -> bool:
        u = self.s.users.get(name)
        if u is not None:
            return bool(u.get("oracle_maintained"))
        r = self.s.roles.get(name)
        return bool(r and r.get("oracle_maintained"))

    def _grantee_exists(self, g: str) -> bool:
        return g == "PUBLIC" or g in self.s.users or g in self.s.roles

    def effective_limit(self, profile: str, resource: str) -> str:
        v = self.s.profiles[profile].get(resource, "DEFAULT")
        return self.s.profiles["DEFAULT"][resource] if v == "DEFAULT" else v

    def _resolve_object(self, obj: str) -> tuple[str, str]:
        if "." in obj:
            o, n = obj.split(".", 1)
            return o.strip('"').upper(), n.strip('"').upper()
        return "SYS", obj.strip('"').upper()

    def _has_definer_access(self, owner: str, obj_owner: str, obj: str) -> bool:
        return any(g in (owner, "PUBLIC") and o == obj_owner and n == obj and p == "EXECUTE"
                   for g, o, n, p, _ in self.s.tab_privs)

    def _invalidate_package_dependents(self, obj_owner: str, obj: str) -> None:
        for d in self.s.dependencies:
            if d["ref_kind"] == "package" and d["ref_owner"] == obj_owner and d["ref_name"] == obj:
                if not self._has_definer_access(d["owner"], obj_owner, obj):
                    self.s.objects[(d["owner"], d["name"], d["type"])] = "INVALID"

    def _invalidate_link_dependents(self, link: str) -> None:
        for d in self.s.dependencies:
            if d["ref_kind"] == "dblink" and d["ref_name"] == link:
                self.s.objects[(d["owner"], d["name"], d["type"])] = "INVALID"

    # ================================================================== execution
    def execute(self, statements: list[Statement]) -> ExecResult:
        res = ExecResult()
        for st in statements:
            try:
                self._exec_one(st)
                res.executed += 1
            except SimError as e:
                res.ok = False
                res.errors.append(f"{st.kind}: {e}")
        return res

    def _exec_one(self, st: Statement) -> None:
        w = st.words
        k = st.kind
        if k == "ALTER SYSTEM":
            return self._alter_system(st)
        if k in ("GRANT", "REVOKE"):
            return self._grant_revoke(st)
        if k == "ALTER USER":
            return self._alter_user(st)
        if k == "CREATE ROLE":
            r = w[2]
            if r in self.s.roles or r in self.s.users:
                raise SimError("ORA-01921: role name conflicts with another user or role name")
            self.s.roles[r] = {"oracle_maintained": False}
            self.s.role_privs.add(("SYS", r, "YES"))
            return None
        if k == "DROP ROLE":
            r = w[2]
            if r not in self.s.roles:
                raise SimError("ORA-01919: role does not exist")
            del self.s.roles[r]
            self.s.role_privs = {x for x in self.s.role_privs if x[1] != r and x[0] != r}
            self.s.sys_privs = {x for x in self.s.sys_privs if x[0] != r}
            self.s.tab_privs = {x for x in self.s.tab_privs if x[0] != r}
            return None
        if k in ("ALTER PROFILE", "CREATE PROFILE"):
            return self._profile(st)
        if k == "DROP PROFILE":
            p = w[2]
            if p not in self.s.profiles or p == "DEFAULT":
                raise SimError("ORA-02380: profile does not exist")
            users = [u for u, d in self.s.users.items() if d["profile"] == p]
            if users and "CASCADE" not in w:
                raise SimError("ORA-02382: profile has users assigned, cannot drop without CASCADE")
            for u in users:
                self.s.users[u]["profile"] = "DEFAULT"
            del self.s.profiles[p]
            return None
        if k == "CREATE AUDIT POLICY":
            return self._create_audit_policy(st)
        if k == "DROP AUDIT POLICY":
            p = w[3]
            if p not in self.s.audit_policies:
                raise SimError("ORA-46357: audit policy not found")
            if p in self.s.enabled_policies:
                raise SimError("ORA-46361: audit policy cannot be dropped as it is currently enabled")
            del self.s.audit_policies[p]
            return None
        if k in ("AUDIT", "NOAUDIT"):
            return self._audit(st)
        if k == "CREATE DATABASE LINK":
            return self._create_link(st)
        if k == "DROP DATABASE LINK":
            public = st.attrs.get("public")
            name = w[4] if public else w[3]
            key = ("PUBLIC" if public else "SYS", name)
            if key not in self.s.db_links:
                raise SimError("ORA-02024: database link not found")
            del self.s.db_links[key]
            self._invalidate_link_dependents(name)
            return None
        raise SimError(f"ORA-00900: statement type {k} not supported by the simulator")

    def _alter_system(self, st: Statement) -> None:
        a = st.attrs
        name = a.get("parameter")
        if name not in self.s.parameters:
            raise SimError("ORA-02065: illegal option for ALTER SYSTEM (unknown parameter)")
        scope = a.get("scope", "BOTH")
        static = not self.s.param_meta.get(name, {}).get("issys_modifiable", True)
        if a.get("action") == "RESET":
            self.s.spparameters.pop(name, None)
            return
        raw = (a.get("value") or "").strip()
        value: str | None = raw[1:-1] if raw.startswith("'") and raw.endswith("'") else raw.upper()
        if value == "":
            value = None
        if static and scope != "SPFILE":
            raise SimError("ORA-02095: specified initialization parameter cannot be modified")
        if scope in ("SPFILE", "BOTH"):
            self.s.spparameters[name] = value if value is not None else ""
        if scope in ("MEMORY", "BOTH"):
            self.s.parameters[name] = value

    def _grant_revoke(self, st: Statement) -> None:
        a = st.attrs
        privs, obj, grantees, opts = a["privileges"], a["object"], a["grantees"], " ".join(a["options"])
        if not grantees:
            raise SimError("ORA-00987: missing or invalid username(s)")
        for g in grantees:
            if not self._grantee_exists(g):
                raise SimError(f"ORA-01917: user or role '{g}' does not exist")
        grant = st.kind == "GRANT"
        for g in grantees:
            for p in privs:
                if obj:
                    owner, name = self._resolve_object(obj)
                    if (owner, name, "PACKAGE") not in self.s.objects and (owner, name, "TABLE") not in self.s.objects:
                        raise SimError("ORA-04042: procedure, function, package, or package body does not exist")
                    rows = {r for r in self.s.tab_privs if r[0] == g and r[1] == owner and r[2] == name and r[3] == p}
                    if grant:
                        self.s.tab_privs.add((g, owner, name, p, "YES" if "GRANT OPTION" in opts else "NO"))
                    else:
                        if not rows:
                            raise SimError("ORA-01927: cannot REVOKE privileges you did not grant")
                        self.s.tab_privs -= rows
                        if p == "EXECUTE":
                            self._invalidate_package_dependents(owner, name)
                elif p in self.s.roles:
                    rows = {r for r in self.s.role_privs if r[0] == g and r[1] == p}
                    if grant:
                        self.s.role_privs -= rows
                        self.s.role_privs.add((g, p, "YES" if "ADMIN OPTION" in opts else "NO"))
                    else:
                        if not rows:
                            raise SimError(f"ORA-01951: ROLE '{p}' not granted to '{g}'")
                        self.s.role_privs -= rows
                else:
                    rows = {r for r in self.s.sys_privs if r[0] == g and r[1] == p}
                    if grant:
                        self.s.sys_privs -= rows
                        self.s.sys_privs.add((g, p, "YES" if "ADMIN OPTION" in opts else "NO"))
                    else:
                        if not rows:
                            raise SimError(f"ORA-01952: system privileges not granted to '{g}'")
                        self.s.sys_privs -= rows

    def _alter_user(self, st: Statement) -> None:
        w = st.words
        u = w[2]
        if u not in self.s.users:
            raise SimError(f"ORA-01918: user '{u}' does not exist")
        if "PROFILE" in w:
            p = w[w.index("PROFILE") + 1]
            if p not in self.s.profiles:
                raise SimError(f"ORA-02380: profile {p} does not exist")
            self.s.users[u]["profile"] = p
        if "IDENTIFIED" in w:
            self.s.users[u]["pwd"] = hashlib.sha1(st.text.encode()).hexdigest()[:12]
            self.s.users[u]["default_pwd"] = False
        if "ACCOUNT" in w:
            self.s.users[u]["account_status"] = "LOCKED" if w[w.index("ACCOUNT") + 1] == "LOCK" else "OPEN"

    def _profile(self, st: Statement) -> None:
        w = st.words
        p = w[2]
        if st.kind == "CREATE PROFILE":
            if p in self.s.profiles:
                raise SimError("ORA-02379: profile already exists")
            self.s.profiles[p] = {r: "DEFAULT" for r in PROFILE_RESOURCES}
        elif p not in self.s.profiles:
            raise SimError(f"ORA-02380: profile {p} does not exist")
        if "LIMIT" not in w:
            return
        toks = [t for t in st.tokens[w.index("LIMIT") + 1:] if not (t.kind == "PUNCT" and t.text == ",")]
        i = 0
        while i + 1 < len(toks):
            res = toks[i].upper
            if res not in PROFILE_RESOURCES:
                raise SimError(f"ORA-02376: invalid or redundant resource {res}")
            j = i + 1
            val_tokens: list[Token] = []
            while j < len(toks) and toks[j].upper not in PROFILE_RESOURCES:
                val_tokens.append(toks[j])
                j += 1
            val = "".join(t.text for t in val_tokens).upper()
            if p == "DEFAULT" and val == "DEFAULT":
                raise SimError("ORA-02377: invalid profile limit DEFAULT for profile DEFAULT")
            if "/" in val:
                n, d = val.split("/", 1)
                val = f"{float(n) / float(d):.4f}".lstrip("0")
            self.s.profiles[p][res] = val
            i = j

    def _create_audit_policy(self, st: Statement) -> None:
        w = st.words
        name = w[3]
        if name in self.s.audit_policies:
            raise SimError("ORA-46358: audit policy already exists")
        opts: list[tuple[str, str]] = []
        stop = {"ROLES", "PRIVILEGES", "ACTIONS", "WHEN", "EVALUATE", "ONLY", "CONTAINER"}
        i = 4
        while i < len(w):
            section = w[i]
            i += 1
            cur: list[str] = []
            items: list[str] = []
            while i < len(w) and w[i] not in stop:
                if w[i] == ",":
                    items.append(" ".join(cur))
                    cur = []
                else:
                    cur.append(w[i])
                i += 1
            if cur:
                items.append(" ".join(cur))
            typ = {"ACTIONS": "STANDARD ACTION", "PRIVILEGES": "SYSTEM PRIVILEGE", "ROLES": "ROLE PRIVILEGE"}.get(section)
            if typ:
                opts += [(it, typ) for it in items if it]
        if not opts:
            raise SimError("ORA-46356: missing or invalid action audit option")
        self.s.audit_policies[name] = opts

    def _audit(self, st: Statement) -> None:
        w = st.words
        if len(w) < 3 or w[1] != "POLICY":
            raise SimError("ORA-46350: only unified audit policies are supported by the simulator")
        p = w[2]
        if p not in self.s.audit_policies:
            raise SimError("ORA-46357: audit policy not found")
        if st.kind == "NOAUDIT":
            if p not in self.s.enabled_policies:
                raise SimError("ORA-46381: policy not enabled")
            del self.s.enabled_policies[p]
            return
        success = failure = "YES"
        if "WHENEVER" in w:
            if "NOT" in w:
                success = "NO"
            else:
                failure = "NO"
        if "BY" in w:
            entity = w[w.index("BY") + 1]
            self.s.enabled_policies[p] = ("BY USER", entity, success, failure)
        elif "EXCEPT" in w:
            self.s.enabled_policies[p] = ("EXCEPT USER", w[w.index("EXCEPT") + 1], success, failure)
        else:
            self.s.enabled_policies[p] = ("BY USER", "ALL USERS", success, failure)

    def _create_link(self, st: Statement) -> None:
        w = st.words
        public = st.attrs.get("public")
        name = w[4] if public else w[3]
        key = ("PUBLIC" if public else "SYS", name)
        if key in self.s.db_links:
            raise SimError("ORA-02011: duplicate database link name")
        user = w[w.index("TO") + 1] if "TO" in w else None
        secret = ""
        if "BY" in w:
            idx = w.index("BY") + 1
            secret = st.tokens[idx].text if idx < len(st.tokens) else ""
        host = next((t.text.strip("'") for t in st.tokens if t.kind == "STRING"), "")
        self.s.db_links[key] = {"username": user or "", "host": host,
                                "secret": hashlib.sha1(secret.encode()).hexdigest()[:12]}

    # ================================================================== snapshot
    def snapshot(self) -> Snapshot:
        s = self.s
        status_counts: dict[tuple[str, str, str], int] = {}
        for (owner, _n, typ), st in s.objects.items():
            status_counts[(owner, typ, st)] = status_counts.get((owner, typ, st), 0) + 1
        return {
            "DBA_USERS": frozenset((u, d["profile"], d["account_status"], d["auth"]) for u, d in s.users.items()),
            "DBA_PROFILES": frozenset((p, r, v) for p, res in s.profiles.items() for r, v in res.items()),
            "DBA_SYS_PRIVS": frozenset(s.sys_privs),
            "DBA_TAB_PRIVS": frozenset(s.tab_privs),
            "DBA_ROLE_PRIVS": frozenset(s.role_privs),
            "DBA_ROLES": frozenset(s.roles),
            "V$PARAMETER": frozenset((k, v) for k, v in s.parameters.items()),
            "V$SPPARAMETER": frozenset(s.spparameters.items()),
            "AUDIT_UNIFIED_POLICIES": frozenset((p, o, t) for p, opts in s.audit_policies.items() for o, t in opts),
            "AUDIT_UNIFIED_ENABLED_POLICIES": frozenset((p, *v) for p, v in s.enabled_policies.items()),
            "DBA_DB_LINKS": frozenset((o, n, d["username"], d["host"]) for (o, n), d in s.db_links.items()),
            "SYS.LINK$": frozenset((o, n, d["secret"]) for (o, n), d in s.db_links.items()),
            "DBA_OBJECTS_STATUS": frozenset((o, t, st, c) for (o, t, st), c in status_counts.items()),
        }

    # ================================================================== invariants
    def evaluate(self, c: Control, listeners: list[str] | None = None) -> frozenset | None:
        s, p = self.s, c.params
        nm = self._oracle_maintained
        k = c.kind
        if k == "parameter":
            name = p["name"].lower()
            if name not in s.parameters:
                return frozenset()
            v = s.parameters[name]
            op = p.get("op", "eq")
            bad = False
            if op == "eq":
                bad = orafile.normalize_value(v if v is not None else "#NULL#") != orafile.normalize_value(str(p["expected"]))
            elif op == "empty":
                bad = bool(v)
            elif op in ("le", "ge"):
                try:
                    n = float(v) if v is not None else None
                except ValueError:
                    n = None
                bad = n is None or (n > float(p["expected"]) if op == "le" else n < float(p["expected"]))
            insts = range(1, int(s.topology.get("instances", 1)) + 1)
            return frozenset((i, name, v) for i in insts) if bad else frozenset()
        if k == "profile_limit":
            res, op = p["resource"].upper(), p.get("op", "le")
            rows = []
            for prof in s.profiles:
                eff = self.effective_limit(prof, res)
                try:
                    num = float(eff)
                except ValueError:
                    num = None
                if op == "le":
                    bad = eff == "UNLIMITED" or num is None or num > float(p["value"])
                elif op == "ge":
                    bad = eff != "UNLIMITED" and (num is None or num < float(p["value"]))
                else:
                    bad = eff in ("NULL", "DEFAULT", "UNLIMITED", "")
                if bad:
                    rows.append((prof, res, eff))
            return frozenset(rows)
        if k == "public_execute":
            obj = p["object"].upper()
            return frozenset(r[:4] for r in s.tab_privs if r[0] == "PUBLIC" and r[1] == p.get("owner", "SYS")
                             and r[2] == obj and r[3] == "EXECUTE")
        if k == "sys_priv":
            if "pattern" in p:
                core = p["pattern"].strip("%").strip()
                match = lambda pr: f" {core} " in f" {pr} "  # noqa: E731
            else:
                privs = {x.upper() for x in p["privileges"]}
                match = lambda pr: pr in privs  # noqa: E731
            return frozenset(r for r in s.sys_privs if match(r[1]) and not nm(r[0]))
        if k == "role_grant":
            roles = {x.upper() for x in p["roles"]}
            return frozenset(r for r in s.role_privs if r[1] in roles and not nm(r[0]))
        if k == "admin_option":
            return frozenset((r[0], r[1]) for r in s.sys_privs if r[2] == "YES" and not nm(r[0]))
        if k == "object_access":
            objs = {x.upper() for x in p["objects"]}
            return frozenset(r[:4] for r in s.tab_privs if r[1] == p.get("owner", "SYS") and r[2] in objs and not nm(r[0]))
        if k == "no_public_db_links":
            return frozenset((o, n, d["host"]) for (o, n), d in s.db_links.items() if o == "PUBLIC")
        if k == "users_default_profile":
            return frozenset((u, d["profile"]) for u, d in s.users.items()
                             if d["profile"] == "DEFAULT" and not d.get("oracle_maintained"))
        if k == "default_passwords":
            return frozenset((u,) for u, d in s.users.items() if d.get("default_pwd") and d["account_status"] == "OPEN")
        if k == "external_auth":
            return frozenset((u, d["auth"]) for u, d in s.users.items()
                             if d["auth"] == "EXTERNAL" and not d.get("oracle_maintained"))
        if k == "audit_action":
            opt = p["option"].upper()
            typ = p.get("option_type", "STANDARD ACTION")
            for pol, opts in s.audit_policies.items():
                if (opt, typ) in opts and s.enabled_policies.get(pol) == ("BY USER", "ALL USERS", "YES", "YES"):
                    return frozenset()
            return frozenset({(opt,)})
        if k == "ora_file":
            text = s.files.get(p.get("file", "").lower(), "")
            return frozenset(orafile.evaluate(text, p, listeners or ["LISTENER"]))
        return None

    # ================================================================== context (simulated GV$/DBA_ views)
    def topology_context(self) -> dict[str, Any]:
        t = self.s.topology
        return {
            "source": "simulator",
            "instances": [{"inst_id": i, "instance_name": f"{t.get('db_name', 'ORCL')}{i}"}
                          for i in range(1, int(t.get("instances", 1)) + 1)],
            "is_rac": int(t.get("instances", 1)) > 1,
            "cdb": True,
            "containers": t.get("containers", []),
            "dataguard": t.get("dataguard", False),
            "exadata_cells": t.get("cells", 0),
            "is_exadata": t.get("cells", 0) > 0,
            "components": t.get("components", []),
            "version": t.get("version", "19.0.0.0.0"),
        }

    def parameter_context(self, name: str) -> dict[str, Any]:
        meta = self.s.param_meta.get(name, {})
        return {
            "name": name,
            "current_value_by_instance": {i: self.s.parameters.get(name)
                                          for i in range(1, int(self.s.topology.get("instances", 1)) + 1)},
            "spfile_value": self.s.spparameters.get(name),
            "issys_modifiable": "IMMEDIATE" if meta.get("issys_modifiable", True) else "FALSE",
            "ispdb_modifiable": "TRUE" if meta.get("ispdb_modifiable", False) else "FALSE",
        }

    def dependency_context(self, control: Control) -> dict[str, Any]:
        p, k = control.params, control.kind
        out: dict[str, Any] = {"source": "simulator"}
        if k == "public_execute":
            obj = p["object"].upper()
            deps = [d for d in self.s.dependencies if d["ref_kind"] == "package" and d["ref_name"] == obj]
            out["dependent_objects"] = [
                {"owner": d["owner"], "name": d["name"], "type": d["type"],
                 "has_direct_grant": any(g == d["owner"] and n == obj and pr == "EXECUTE"
                                         for g, _o, n, pr, _ in self.s.tab_privs),
                 "status": self.s.objects.get((d["owner"], d["name"], d["type"]))} for d in deps]
            out["recent_sql_modules"] = [d.get("module") for d in deps if d.get("module")]
        elif k == "no_public_db_links":
            out["public_links"] = [{"owner": o, "db_link": n, "username": d["username"], "host": d["host"]}
                                   for (o, n), d in self.s.db_links.items() if o == "PUBLIC"]
            out["dependent_objects"] = [{"owner": d["owner"], "name": d["name"], "type": d["type"], "link": d["ref_name"],
                                         "last_executed_days_ago": d.get("last_executed_days_ago")}
                                        for d in self.s.dependencies if d["ref_kind"] == "dblink"]
        elif k == "profile_limit":
            res = p["resource"].upper()
            out["profiles"] = [{"profile": pr, "limit": self.s.profiles[pr].get(res), "effective": self.effective_limit(pr, res),
                                "users": sorted(u for u, d in self.s.users.items() if d["profile"] == pr)}
                               for pr in self.s.profiles]
        elif k in ("sys_priv", "role_grant", "admin_option", "object_access"):
            rows = self.evaluate(control) or frozenset()
            grantees = sorted({r[0] for r in rows})
            out["grantees"] = [{"grantee": g, "type": "USER" if g in self.s.users else "ROLE",
                                "owned_objects": sum(1 for (o, _n, _t) in self.s.objects if o == g)} for g in grantees]
            if k == "admin_option":
                out["admin_grants"] = sorted(rows)
        elif k == "users_default_profile":
            out["users"] = sorted(u for u, d in self.s.users.items()
                                  if d["profile"] == "DEFAULT" and not d.get("oracle_maintained"))
            out["existing_profiles"] = sorted(self.s.profiles)
        elif k == "audit_action":
            out["policies"] = {pol: [o for o, _ in opts] for pol, opts in self.s.audit_policies.items()}
            out["enabled"] = {pol: list(v) for pol, v in self.s.enabled_policies.items()}
        elif k == "parameter":
            out["parameter"] = self.parameter_context(p["name"].lower())
        elif k == "ora_file":
            out["file_entries"] = orafile.as_dict(self.s.files.get(p.get("file", "").lower(), ""))
        return out


class SimulatedSandbox(Sandbox):
    """Shadow copy of a :class:`SimulatedOracle` (the simulator's 'snapshot clone')."""

    name = "simulated-shadow"

    def __init__(self, source: SimulatedOracle, listeners: list[str] | None = None):
        self.db = source.clone()
        self.listeners = listeners or ["LISTENER"]

    def can_evaluate(self, control: Control) -> bool:
        return control.kind not in ("manual", "custom")

    def evaluate_invariant(self, control: Control) -> frozenset | None:
        return self.db.evaluate(control, self.listeners)

    def snapshot(self) -> Snapshot:
        snap = self.db.snapshot()
        for f, text in self.db.s.files.items():
            snap[f"FILE:{f}"] = frozenset(orafile.as_dict(text).items())
        return snap

    def execute(self, statements: list[Statement]) -> ExecResult:
        file_stmts = [s for s in statements if s.kind in ("ORA_SET", "ORA_UNSET")]
        sql_stmts = [s for s in statements if s.kind not in ("ORA_SET", "ORA_UNSET")]
        res = self.db.execute(sql_stmts) if sql_stmts else ExecResult()
        for st in file_stmts:
            a = st.attrs
            f = (a.get("file") or "").lower()
            if a.get("malformed") or f not in self.db.s.files:
                res.ok = False
                res.errors.append(f"{st.kind}: unknown file {f!r}")
                continue
            txt = self.db.s.files[f]
            self.db.s.files[f] = orafile.set_key(txt, a["key"], a["value"]) if st.kind == "ORA_SET" \
                else orafile.unset_key(txt, a["key"])
            res.executed += 1
        return res
