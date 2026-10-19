"""Live context sources: topology and dependency context (paper Section III.B).

Topology context
    GV$INSTANCE (instance count/names), V$CONTAINERS (open PDBs with CON_IDs),
    GV$DATAGUARD_CONFIG (standby presence), DBA_REGISTRY (components), plus
    V$DATABASE and V$CELL (Exadata storage cells) -- establishes single-instance
    vs RAC, Data Guard presence and Exadata options.

Dependency context
    DBA_OBJECTS, DBA_DEPENDENCIES, DBA_TAB_PRIVS and recent SQL.  Recent SQL is
    read from GV$SQL by default.  The paper's rolling 24-hour AWR top-SQL window
    (DBA_HIST_*) requires the Oracle Diagnostics Pack licence, so it is opt-in
    (``context.awr.enabled``) and additionally gated on
    CONTROL_MANAGEMENT_PACK_ACCESS containing DIAGNOSTIC.

Every query is wrapped: an ORA- error becomes context ("error": ...) and never
aborts assembly.
"""

from __future__ import annotations

from typing import Any, Protocol

from ..controls import Control
from ..models import Finding
from ..verify import orafile


class ContextSource(Protocol):
    def topology(self) -> dict[str, Any]: ...

    def dependencies(self, control: Control, finding: Finding) -> dict[str, Any]: ...


class SimulatedContextSource:
    def __init__(self, db):
        self.db = db

    def topology(self) -> dict[str, Any]:
        return self.db.topology_context()

    def dependencies(self, control: Control, finding: Finding) -> dict[str, Any]:
        return self.db.dependency_context(control)


def _binds(prefix: str, values: list[str]) -> tuple[str, dict[str, str]]:
    names = [f":{prefix}{i}" for i in range(len(values))]
    return ", ".join(names) or "NULL", {f"{prefix}{i}": v for i, v in enumerate(values)}


class OracleContextSource:
    def __init__(self, client, cfg, files: dict[str, str | None] | None = None):
        self.c = client
        self.cfg = cfg
        self.files = files or {}
        self.max_rows = int(cfg.get("context.max_rows_per_query", 50))
        self._awr_ok: bool | None = None

    # ------------------------------------------------------------------ topology
    def topology(self) -> dict[str, Any]:
        c = self.c
        c.set_container("CDB$ROOT")
        q = c.try_query
        inst = q("SELECT inst_id, instance_name, host_name, version, status FROM gv$instance ORDER BY inst_id")
        db = q("SELECT name, db_unique_name, cdb, database_role, open_mode FROM v$database")
        cont = q("SELECT con_id, name, open_mode FROM v$containers ORDER BY con_id")
        dg = q("SELECT * FROM gv$dataguard_config", max_rows=self.max_rows)
        reg = q("SELECT comp_id, version, status FROM dba_registry ORDER BY comp_id")
        cells = q("SELECT COUNT(*) FROM v$cell")
        n_inst = len(inst.get("rows", []))
        n_cells = cells.get("rows", [[0]])[0][0] if "rows" in cells else 0
        dg_rows = dg.get("rows", [])
        return {
            "source": "oracle",
            "instances": [dict(zip(["inst_id", "instance_name", "host_name", "version", "status"], r))
                          for r in inst.get("rows", [])],
            "is_rac": n_inst > 1,
            "database": dict(zip(["name", "db_unique_name", "cdb", "database_role", "open_mode"],
                                 (db.get("rows") or [[None] * 5])[0])),
            "containers": [dict(zip(["con_id", "name", "open_mode"], r)) for r in cont.get("rows", [])],
            # GV$DATAGUARD_CONFIG lists the primary itself; >1 distinct member means a standby exists
            "dataguard": len({tuple(r) for r in dg_rows}) > 1,
            "dataguard_config": [list(map(str, r)) for r in dg_rows][: self.max_rows],
            "components": [r[0] for r in reg.get("rows", [])],
            "exadata_cells": n_cells,
            "is_exadata": n_cells > 0,
            "errors": {k: v["error"] for k, v in
                       {"gv$instance": inst, "v$database": db, "v$containers": cont, "gv$dataguard_config": dg,
                        "dba_registry": reg, "v$cell": cells}.items() if "error" in v},
        }

    # ------------------------------------------------------------------ dependency
    def _awr_allowed(self) -> bool:
        if not self.cfg.get("context.awr.enabled"):
            return False
        if self._awr_ok is None:
            r = self.c.try_query("SELECT value FROM v$parameter WHERE name = 'control_management_pack_access'")
            self._awr_ok = "DIAGNOSTIC" in str(r.get("rows", "")).upper()
        return self._awr_ok

    def _recent_sql(self, needle: str) -> dict[str, Any]:
        out = {"gv$sql": self.c.try_query(
            "SELECT parsing_schema_name, module, COUNT(*) AS cursors, MAX(last_active_time) AS last_active\n"
            "  FROM gv$sql WHERE UPPER(sql_text) LIKE '%' || :n || '%'\n"
            " GROUP BY parsing_schema_name, module ORDER BY cursors DESC",
            {"n": needle.upper()}, int(self.cfg.get("context.top_sql_limit", 20)))}
        if self._awr_allowed():
            out["awr"] = self.c.try_query(
                "SELECT s.parsing_schema_name, s.module, COUNT(DISTINCT s.sql_id), SUM(s.executions_delta)\n"
                "  FROM dba_hist_sqlstat s\n"
                "  JOIN dba_hist_snapshot sn ON sn.snap_id = s.snap_id AND sn.dbid = s.dbid\n"
                "   AND sn.instance_number = s.instance_number\n"
                "  JOIN dba_hist_sqltext t ON t.sql_id = s.sql_id AND t.dbid = s.dbid\n"
                " WHERE sn.begin_interval_time > SYSTIMESTAMP - NUMTODSINTERVAL(:h, 'HOUR')\n"
                "   AND DBMS_LOB.INSTR(UPPER(t.sql_text), :n) > 0\n"
                " GROUP BY s.parsing_schema_name, s.module ORDER BY 4 DESC NULLS LAST",
                {"h": int(self.cfg.get("context.awr.window_hours", 24)), "n": needle.upper()},
                int(self.cfg.get("context.top_sql_limit", 20)))
        else:
            out["awr"] = {"skipped": "AWR disabled or Diagnostics Pack not enabled (licence)"}
        return out

    def dependencies(self, control: Control, finding: Finding) -> dict[str, Any]:
        k, p = control.kind, control.params
        q = self.c.try_query
        out: dict[str, Any] = {"source": "oracle"}
        if control.is_file_control:
            path = self.files.get(p.get("file", "").replace(".", "_"))
            try:
                out["file_entries"] = orafile.as_dict(open(path).read()) if path else {}
            except OSError as e:
                out["file_entries"] = {"error": str(e)}
            return out
        container = finding.container if finding.container not in ("HOST",) else "CDB$ROOT"
        self.c.set_container(container)
        if k == "parameter":
            name = p["name"].lower()
            out["parameter"] = {
                "by_instance": q("SELECT inst_id, value, isdefault, ismodified, issys_modifiable, ispdb_modifiable\n"
                                 "  FROM gv$parameter WHERE name = :n ORDER BY inst_id", {"n": name}),
                "spfile": q("SELECT sid, value FROM v$spparameter WHERE name = :n AND isspecified = 'TRUE'", {"n": name}),
            }
            rows = out["parameter"]["by_instance"].get("rows") or []
            if rows:
                out["parameter"]["issys_modifiable"] = rows[0][4]
                out["parameter"]["ispdb_modifiable"] = rows[0][5]
        elif k == "public_execute":
            obj = p["object"].upper()
            out["dependent_objects"] = q(
                "SELECT d.owner, d.name, d.type, o.status,\n"
                "       (SELECT COUNT(*) FROM dba_tab_privs t WHERE t.grantee = d.owner AND t.owner = 'SYS'\n"
                "           AND t.table_name = d.referenced_name AND t.privilege = 'EXECUTE') AS direct_grants\n"
                "  FROM dba_dependencies d\n"
                "  JOIN dba_objects o ON o.owner = d.owner AND o.object_name = d.name AND o.object_type = d.type\n"
                " WHERE d.referenced_owner IN ('SYS', 'PUBLIC') AND d.referenced_name = :obj\n"
                "   AND d.owner NOT IN (SELECT username FROM dba_users WHERE oracle_maintained = 'Y')",
                {"obj": obj}, self.max_rows)
            # COMMON='YES' means the PUBLIC grant was made in the root: it can only be revoked
            # from CDB$ROOT with CONTAINER=ALL (affects every PDB) -- a CDB-scope remediation.
            out["public_grant"] = q("SELECT grantee, privilege, common, inherited FROM dba_tab_privs\n"
                                    " WHERE grantee = 'PUBLIC' AND owner = 'SYS' AND table_name = :obj",
                                    {"obj": obj})
            out["recent_sql"] = self._recent_sql(obj)
        elif k == "no_public_db_links":
            out["public_links"] = q("SELECT owner, db_link, username, host FROM dba_db_links WHERE owner = 'PUBLIC'")
            out["dependent_objects"] = q(
                "SELECT d.owner, d.name, d.type, d.referenced_link_name, o.status, o.last_ddl_time\n"
                "  FROM dba_dependencies d JOIN dba_objects o\n"
                "    ON o.owner = d.owner AND o.object_name = d.name AND o.object_type = d.type\n"
                " WHERE d.referenced_link_name IS NOT NULL", max_rows=self.max_rows)
            links = [r[1] for r in out["public_links"].get("rows", [])]
            out["recent_sql"] = {lk: self._recent_sql("@" + lk.split(".")[0]) for lk in links[:5]}
        elif k == "profile_limit":
            res = p["resource"].upper()
            out["profiles"] = q("SELECT profile, limit FROM dba_profiles WHERE resource_name = :r", {"r": res})
            out["users_by_profile"] = q("SELECT profile, COUNT(*) FROM dba_users WHERE oracle_maintained = 'N' "
                                        "GROUP BY profile")
            if res == "PASSWORD_VERIFY_FUNCTION":
                out["verify_functions"] = q("SELECT object_name FROM dba_procedures WHERE owner = 'SYS' "
                                            "AND object_name LIKE 'ORA%VERIFY_FUNCTION'")
        elif k in ("sys_priv", "role_grant", "admin_option", "object_access", "users_default_profile",
                   "external_auth", "default_passwords"):
            grantees = [g for g in finding.affected_grantees if g][:50]
            inl, binds = _binds("g", grantees)
            out["grantees"] = q(f"SELECT username, account_status, profile, authentication_type FROM dba_users "
                                f"WHERE username IN ({inl})", binds)
            out["owned_objects"] = q(f"SELECT owner, object_type, COUNT(*) FROM dba_objects WHERE owner IN ({inl}) "
                                     "GROUP BY owner, object_type", binds)
            out["active_sessions"] = q(f"SELECT username, module, COUNT(*) FROM gv$session WHERE username IN ({inl}) "
                                       "GROUP BY username, module", binds)
        elif k == "audit_action":
            out["enabled_policies"] = q("SELECT policy_name, enabled_option, entity_name, success, failure "
                                        "FROM audit_unified_enabled_policies")
            out["policy_options"] = q("SELECT policy_name, audit_option FROM audit_unified_policies "
                                      "WHERE audit_option = :o", {"o": p["option"].upper()})
        return out
