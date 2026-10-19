from oracle_remediate.sim.simulator import SimulatedSandbox
from oracle_remediate.verify.orafile import as_dict, evaluate, set_key, unset_key
from oracle_remediate.verify.sqltools import parse_script
from oracle_remediate.verify.verifier import VerifierSettings, verify_candidate


def test_audit_invariants_detect_seeded_violations(db, catalog):
    assert db.evaluate(catalog.get("ch4.no_public_db_links"))
    assert db.evaluate(catalog.get("ch6.public_exec_utl_file"))
    assert not db.evaluate(catalog.get("ch5.audit_create_user"))  # covered by the seeded policy
    assert db.evaluate(catalog.get("ch5.audit_grant"))


def test_static_parameter_rejects_memory_scope(db):
    r = db.execute(parse_script("ALTER SYSTEM SET audit_sys_operations=TRUE SCOPE=BOTH"))
    assert not r.ok and "ORA-02095" in r.errors[0]
    assert db.execute(parse_script("ALTER SYSTEM SET audit_sys_operations=TRUE SCOPE=SPFILE")).ok


def test_revoke_from_public_invalidates_dependent_code(db):
    db.execute(parse_script("REVOKE EXECUTE ON SYS.UTL_FILE FROM PUBLIC"))
    assert db.s.objects[("APP_OWNER", "FILE_LOGGER", "PACKAGE BODY")] == "INVALID"


def test_direct_grant_first_keeps_code_valid(db):
    db.execute(parse_script("GRANT EXECUTE ON SYS.UTL_FILE TO APP_OWNER; REVOKE EXECUTE ON SYS.UTL_FILE FROM PUBLIC"))
    assert db.s.objects[("APP_OWNER", "FILE_LOGGER", "PACKAGE BODY")] == "VALID"


def test_layer3_detects_cascade_and_hard_floor_inputs(db, catalog):
    c = catalog.get("ch6.public_exec_utl_file")
    with SimulatedSandbox(db) as sb:
        ver, rb = verify_candidate("REVOKE EXECUTE ON SYS.UTL_FILE FROM PUBLIC;",
                                   "GRANT EXECUTE ON SYS.UTL_FILE TO PUBLIC;", c, catalog, sb, VerifierSettings())
    assert ver.L1.passed == 1 and ver.L2.passed == 1
    assert ver.L3.passed == 0 and "DBA_OBJECTS_STATUS" in ver.L3.detail
    assert rb.L_RB.passed == 0  # invalidated object stays invalid after re-grant


def test_context_aware_fix_passes_all_layers(db, catalog):
    c = catalog.get("ch6.public_exec_utl_file")
    with SimulatedSandbox(db) as sb:
        ver, rb = verify_candidate(
            "GRANT EXECUTE ON SYS.UTL_FILE TO APP_OWNER;\nREVOKE EXECUTE ON SYS.UTL_FILE FROM PUBLIC;",
            "GRANT EXECUTE ON SYS.UTL_FILE TO PUBLIC;\nREVOKE EXECUTE ON SYS.UTL_FILE FROM APP_OWNER;",
            c, catalog, sb, VerifierSettings())
    assert (ver.L1.passed, ver.L2.passed, ver.L3.passed, rb.L_RB.passed) == (1, 1, 1, 1)


def test_l1_failure_is_never_executed(db, catalog):
    c = catalog.get("ch6.public_exec_utl_file")
    with SimulatedSandbox(db) as sb:
        ver, rb = verify_candidate("DROP USER SCOTT CASCADE; REVOKE EXECUTE ON SYS.UTL_FILE FROM PUBLIC;",
                                   "GRANT EXECUTE ON SYS.UTL_FILE TO PUBLIC;", c, catalog, sb, VerifierSettings())
        assert "SCOTT" in sb.db.s.users  # nothing ran
    assert not ver.executed and ver.L3.passed == 0 and rb.L_RB.passed == 0


def test_sandbox_isolation(db, catalog):
    with SimulatedSandbox(db) as sb:
        sb.execute(parse_script("REVOKE EXECUTE ON SYS.UTL_TCP FROM PUBLIC"))
    assert db.evaluate(catalog.get("ch6.public_exec_utl_tcp"))  # source untouched


def test_orafile_roundtrip():
    text = "LISTENER =\n  (DESCRIPTION =\n    (ADDRESS = (PROTOCOL = TCP)(HOST = h)(PORT = 1521))\n  )\nX = 1\n"
    d = as_dict(text)
    assert "LISTENER" in d and "PORT=1521" in d["LISTENER"].replace(" ", "") and d["X"] == "1"
    t2 = set_key(text, "ADMIN_RESTRICTIONS_LISTENER", "ON")
    assert evaluate(t2, {"key": "ADMIN_RESTRICTIONS_{listener}", "op": "eq", "expected": "ON"}, ["LISTENER"]) == []
    assert unset_key(t2, "ADMIN_RESTRICTIONS_LISTENER") == text
