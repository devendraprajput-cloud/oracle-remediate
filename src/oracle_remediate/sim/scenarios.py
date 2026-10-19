"""Deterministic benchmark scenario for the simulator (paper Section IV.C).

Seeds a container database with induced violations for the reference catalog
across the paper's three topology profiles: ``single`` (single-instance,
non-RAC), ``rac2`` (two-node RAC) and ``exadata`` (simulated Exadata X10M
profile with ASM cells and a Data Guard standby).  The same violations are
induced on a real database by ``benchmark/seed/*.sql``.

Values in this module are simulator inputs, not statements about Oracle
defaults.
"""

from __future__ import annotations

from .simulator import PROFILE_RESOURCES, SimState, SimulatedOracle

TOPOLOGIES = {
    "single": {"db_name": "ORCL", "instances": 1, "cells": 0, "dataguard": False,
               "containers": [{"con_id": 1, "name": "CDB$ROOT", "open_mode": "READ WRITE"},
                              {"con_id": 2, "name": "PDB$SEED", "open_mode": "READ ONLY"},
                              {"con_id": 3, "name": "SALES_PDB", "open_mode": "READ WRITE"}],
               "components": ["CATALOG", "CATPROC", "XDB", "OWM"]},
    "rac2": {"db_name": "ORCL", "instances": 2, "cells": 0, "dataguard": False,
             "containers": [{"con_id": 1, "name": "CDB$ROOT", "open_mode": "READ WRITE"},
                            {"con_id": 2, "name": "PDB$SEED", "open_mode": "READ ONLY"},
                            {"con_id": 3, "name": "SALES_PDB", "open_mode": "READ WRITE"}],
             "components": ["CATALOG", "CATPROC", "RAC", "XDB", "OWM"]},
    "exadata": {"db_name": "ORCL", "instances": 2, "cells": 3, "dataguard": True,
                "containers": [{"con_id": 1, "name": "CDB$ROOT", "open_mode": "READ WRITE"},
                               {"con_id": 2, "name": "PDB$SEED", "open_mode": "READ ONLY"},
                               {"con_id": 3, "name": "SALES_PDB", "open_mode": "READ WRITE"}],
                "components": ["CATALOG", "CATPROC", "RAC", "XDB", "OWM", "JAVAVM"]},
}

STATIC_PARAMS = {"audit_sys_operations", "os_roles", "remote_os_roles", "remote_login_passwordfile",
                 "sec_max_failed_login_attempts", "sec_return_server_release_banner", "sql92_security"}
PDB_MODIFIABLE = {"global_names", "resource_limit"}

SYS_PACKAGES = ["UTL_TCP", "UTL_SMTP", "UTL_HTTP", "UTL_INADDR", "UTL_FILE", "DBMS_LDAP", "DBMS_LOB",
                "DBMS_ADVISOR", "DBMS_CRYPTO", "DBMS_RANDOM", "DBMS_SCHEDULER", "DBMS_JOB", "DBMS_SQL",
                "DBMS_XMLGEN", "DBMS_BACKUP_RESTORE"]
PUBLIC_EXECUTE = ["UTL_TCP", "UTL_SMTP", "UTL_HTTP", "UTL_INADDR", "UTL_FILE", "DBMS_LDAP", "DBMS_LOB",
                  "DBMS_ADVISOR", "DBMS_RANDOM", "DBMS_JOB", "DBMS_SQL", "DBMS_XMLGEN"]

SQLNET_ORA = """# sqlnet.ora (benchmark seed)
NAMES.DIRECTORY_PATH = (TNSNAMES, EZCONNECT)
SQLNET.ENCRYPTION_SERVER = ACCEPTED
SQLNET.CRYPTO_CHECKSUM_SERVER = ACCEPTED
"""

LISTENER_ORA = """# listener.ora (benchmark seed)
LISTENER =
  (DESCRIPTION_LIST =
    (DESCRIPTION =
      (ADDRESS = (PROTOCOL = TCP)(HOST = dbhost)(PORT = 1521))
    )
  )
ADMIN_RESTRICTIONS_LISTENER = OFF
"""


def build_state(profile: str = "single") -> SimState:
    topo = dict(TOPOLOGIES[profile])
    rac = topo["instances"] > 1
    params = {
        "audit_sys_operations": "FALSE", "global_names": "FALSE", "os_roles": "FALSE",
        "remote_listener": "orcl-scan:1521" if rac else None,
        "remote_login_passwordfile": "EXCLUSIVE", "remote_os_roles": "FALSE",
        "sec_max_failed_login_attempts": "10", "sec_protocol_error_further_action": "CONTINUE",
        "sec_protocol_error_trace_action": "TRACE", "sec_return_server_release_banner": "FALSE",
        "sql92_security": "FALSE", "resource_limit": "FALSE",
    }
    meta = {n: {"issys_modifiable": n not in STATIC_PARAMS, "ispdb_modifiable": n in PDB_MODIFIABLE} for n in params}
    default = {r: "UNLIMITED" for r in PROFILE_RESOURCES}
    default.update({"FAILED_LOGIN_ATTEMPTS": "10", "PASSWORD_LOCK_TIME": "1", "PASSWORD_LIFE_TIME": "180",
                    "PASSWORD_GRACE_TIME": "7", "PASSWORD_VERIFY_FUNCTION": "NULL",
                    "PASSWORD_REUSE_MAX": "UNLIMITED", "PASSWORD_REUSE_TIME": "UNLIMITED"})
    app_profile = {r: "DEFAULT" for r in PROFILE_RESOURCES}
    app_profile.update({"PASSWORD_LIFE_TIME": "UNLIMITED", "SESSIONS_PER_USER": "200"})
    users = {
        "SYS": {"profile": "DEFAULT", "account_status": "OPEN", "oracle_maintained": True, "auth": "PASSWORD"},
        "SYSTEM": {"profile": "DEFAULT", "account_status": "OPEN", "oracle_maintained": True, "auth": "PASSWORD"},
        "DBSNMP": {"profile": "DEFAULT", "account_status": "LOCKED", "oracle_maintained": True, "auth": "PASSWORD"},
        "APP_OWNER": {"profile": "APP_PROFILE", "account_status": "OPEN", "oracle_maintained": False, "auth": "PASSWORD"},
        "REPORTING": {"profile": "DEFAULT", "account_status": "OPEN", "oracle_maintained": False, "auth": "PASSWORD"},
        "SCOTT": {"profile": "DEFAULT", "account_status": "OPEN", "oracle_maintained": False, "auth": "PASSWORD",
                  "default_pwd": True},
        "OPS$BATCH": {"profile": "APP_PROFILE", "account_status": "OPEN", "oracle_maintained": False, "auth": "EXTERNAL"},
        "MONITOR_SVC": {"profile": "APP_PROFILE", "account_status": "OPEN", "oracle_maintained": False, "auth": "PASSWORD"},
    }
    roles = {r: {"oracle_maintained": True} for r in ["DBA", "SELECT_CATALOG_ROLE", "EXECUTE_CATALOG_ROLE",
                                                      "CONNECT", "RESOURCE", "AUDIT_ADMIN"]}
    roles["APP_RW"] = {"oracle_maintained": False}
    objects = {("SYS", p, "PACKAGE"): "VALID" for p in SYS_PACKAGES}
    objects.update({("SYS", t, "TABLE"): "VALID" for t in ["USER$", "LINK$", "USER_HISTORY$", "SCHEDULER$_CREDENTIAL",
                                                           "XS$VERIFIERS"]})
    objects.update({
        ("APP_OWNER", "FILE_LOGGER", "PACKAGE BODY"): "VALID",
        ("APP_OWNER", "ORDERS", "TABLE"): "VALID",
        ("APP_OWNER", "V_REMOTE_ORDERS", "VIEW"): "VALID",
        ("APP_OWNER", "V_REMOTE_STOCK", "VIEW"): "VALID",
        ("APP_OWNER", "SYNC_PKG", "PACKAGE BODY"): "VALID",
        ("REPORTING", "RPT_PKG", "PACKAGE BODY"): "VALID",
    })
    deps = [
        {"owner": "APP_OWNER", "name": "FILE_LOGGER", "type": "PACKAGE BODY", "ref_kind": "package",
         "ref_owner": "SYS", "ref_name": "UTL_FILE", "module": "order-entry-batch"},
        {"owner": "REPORTING", "name": "RPT_PKG", "type": "PACKAGE BODY", "ref_kind": "package",
         "ref_owner": "SYS", "ref_name": "DBMS_LOB", "module": "nightly-reports"},
        {"owner": "APP_OWNER", "name": "V_REMOTE_ORDERS", "type": "VIEW", "ref_kind": "dblink", "ref_name": "REMOTE_SALES"},
        {"owner": "APP_OWNER", "name": "V_REMOTE_STOCK", "type": "VIEW", "ref_kind": "dblink", "ref_name": "REMOTE_SALES"},
        {"owner": "APP_OWNER", "name": "SYNC_PKG", "type": "PACKAGE BODY", "ref_kind": "dblink",
         "ref_name": "REMOTE_SALES", "last_executed_days_ago": "41"},
    ]
    tab_privs = {("PUBLIC", "SYS", p, "EXECUTE", "NO") for p in PUBLIC_EXECUTE}
    tab_privs |= {("REPORTING", "SYS", "USER$", "SELECT", "NO"), ("APP_RW", "APP_OWNER", "ORDERS", "SELECT", "NO")}
    sys_privs = {
        ("SYS", "SELECT ANY TABLE", "YES"), ("DBA", "SELECT ANY TABLE", "YES"),
        ("APP_OWNER", "CREATE SESSION", "NO"), ("APP_OWNER", "CREATE TABLE", "NO"),
        ("APP_OWNER", "SELECT ANY TABLE", "NO"),
        ("REPORTING", "CREATE SESSION", "YES"), ("REPORTING", "SELECT ANY DICTIONARY", "NO"),
        ("MONITOR_SVC", "CREATE SESSION", "NO"),
    }
    role_privs = {("SYS", "DBA", "YES"), ("APP_OWNER", "DBA", "NO"), ("MONITOR_SVC", "SELECT_CATALOG_ROLE", "NO"),
                  ("APP_OWNER", "APP_RW", "YES")}
    audit_policies = {"ORA_SECURECONFIG": [("CREATE USER", "STANDARD ACTION"), ("DROP USER", "STANDARD ACTION")],
                      "ORA_LOGON_FAILURES": [("LOGON", "STANDARD ACTION")]}
    enabled = {"ORA_SECURECONFIG": ("BY USER", "ALL USERS", "YES", "YES"),
               "ORA_LOGON_FAILURES": ("BY USER", "ALL USERS", "NO", "YES")}
    links = {("PUBLIC", "REMOTE_SALES"): {"username": "SALES_RO", "host": "salesdb", "secret": "a1b2c3d4e5f6"},
             ("APP_OWNER", "HR_LINK"): {"username": "HR_RO", "host": "hrdb", "secret": "0f9e8d7c6b5a"}}
    return SimState(
        topology=topo, parameters=params, param_meta=meta, spparameters={k: v or "" for k, v in params.items()},
        profiles={"DEFAULT": default, "APP_PROFILE": app_profile}, users=users, roles=roles,
        sys_privs=sys_privs, tab_privs=tab_privs, role_privs=role_privs, audit_policies=audit_policies,
        enabled_policies=enabled, db_links=links, objects=objects, dependencies=deps,
        files={"sqlnet.ora": SQLNET_ORA, "listener.ora": LISTENER_ORA},
    )


def build_database(profile: str = "single") -> SimulatedOracle:
    if profile not in TOPOLOGIES:
        raise ValueError(f"unknown topology profile {profile!r}; choose from {sorted(TOPOLOGIES)}")
    return SimulatedOracle(build_state(profile))
