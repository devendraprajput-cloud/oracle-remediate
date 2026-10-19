from oracle_remediate.verify.static_check import static_check


def test_whitelisted_revoke_passes(catalog):
    c = catalog.get("ch6.public_exec_utl_file")
    r = static_check("REVOKE EXECUTE ON SYS.UTL_FILE FROM PUBLIC;", "GRANT EXECUTE ON SYS.UTL_FILE TO PUBLIC;", c)
    assert r.passed == 1, r.detail


def test_forbidden_statement_fails(catalog):
    c = catalog.get("ch6.public_exec_utl_file")
    r = static_check("DROP USER SCOTT CASCADE; REVOKE EXECUTE ON SYS.UTL_FILE FROM PUBLIC;",
                     "GRANT EXECUTE ON SYS.UTL_FILE TO PUBLIC;", c)
    assert r.passed == 0 and "UnsafeStatement(DROP USER)" in r.detail


def test_out_of_scope_kind_fails(catalog):
    c = catalog.get("ch3.failed_login_attempts")
    r = static_check("ALTER SYSTEM SET resource_limit=TRUE;", "ALTER SYSTEM SET resource_limit=FALSE;", c)
    assert r.passed == 0 and "OutOfScope(ALTER SYSTEM, ch3_prof)" in r.detail


def test_alter_system_must_target_control_parameter(catalog):
    c = catalog.get("ch2.global_names")
    r = static_check("ALTER SYSTEM SET resource_limit=TRUE SCOPE=BOTH;", "ALTER SYSTEM SET resource_limit=FALSE;", c)
    assert r.passed == 0 and "targets 'resource_limit'" in r.detail


def test_privilege_escalation_guard(catalog):
    c = catalog.get("ch6.no_dba_role")
    r = static_check("REVOKE DBA FROM APP; GRANT SELECT ANY TABLE TO APP;", "GRANT DBA TO APP; REVOKE SELECT ANY TABLE FROM APP;", c)
    assert r.passed == 0 and "privilege-escalation guard" in r.detail


def test_rollback_inverse_check(catalog):
    c = catalog.get("ch6.public_exec_utl_file")
    r = static_check("REVOKE EXECUTE ON SYS.UTL_FILE FROM PUBLIC;", "GRANT DBA TO SCOTT;", c)
    assert r.passed == 0 and "does not restore a revoked privilege" in r.detail


def test_password_change_rejected(catalog):
    c = catalog.get("ch4.users_not_default_profile")
    r = static_check("ALTER USER SCOTT IDENTIFIED BY x;", "ALTER USER SCOTT PROFILE DEFAULT;", c)
    assert r.passed == 0 and "non-invertible" in r.detail


def test_empty_rollback_fails(catalog):
    c = catalog.get("ch2.global_names")
    assert static_check("ALTER SYSTEM SET global_names=TRUE;", "", c).passed == 0


def test_ora_file_target(catalog):
    c = catalog.get("ch2.sqlnet_encryption_server")
    ok = static_check("ORA_SET sqlnet.ora SQLNET.ENCRYPTION_SERVER = REQUIRED",
                      "ORA_SET sqlnet.ora SQLNET.ENCRYPTION_SERVER = ACCEPTED", c)
    bad = static_check("ORA_SET listener.ora SQLNET.ENCRYPTION_SERVER = REQUIRED",
                       "ORA_UNSET sqlnet.ora SQLNET.ENCRYPTION_SERVER", c)
    assert ok.passed == 1 and bad.passed == 0
