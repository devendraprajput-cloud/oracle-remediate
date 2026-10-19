from oracle_remediate.verify.sqltools import canonicalize, classify, parse_script, split_statements


def test_split_respects_quotes_and_comments():
    sql = "-- c1\nGRANT EXECUTE ON SYS.UTL_FILE TO app; /* x; y */ ALTER SYSTEM SET x = 'a;b' SCOPE=BOTH;"
    stmts = split_statements(sql)
    assert len(stmts) == 2
    assert stmts[1].endswith("SCOPE=BOTH")


def test_plsql_block_is_not_split_and_is_classified():
    sql = "BEGIN\n  EXECUTE IMMEDIATE 'DROP USER x';\n  NULL;\nEND;\n/\nREVOKE DBA FROM app;"
    st = parse_script(sql)
    assert [s.kind for s in st] == ["PLSQL_BLOCK", "REVOKE"]


def test_classification_of_key_kinds():
    assert classify("ALTER SYSTEM SET audit_sys_operations=TRUE SCOPE=SPFILE").kind == "ALTER SYSTEM"
    assert classify("ALTER SYSTEM KILL SESSION '1,2'").kind == "ALTER SYSTEM OTHER"
    assert classify("DROP PUBLIC DATABASE LINK foo").kind == "DROP DATABASE LINK"
    assert classify("create audit policy p actions create user").kind == "CREATE AUDIT POLICY"
    assert classify("exec dbms_output.put_line('x')").kind == "PLSQL_BLOCK"
    assert classify("host rm -rf /").kind == "HOST"
    assert classify("ORA_SET sqlnet.ora SQLNET.ENCRYPTION_SERVER = REQUIRED").attrs["key"] == "SQLNET.ENCRYPTION_SERVER"


def test_alter_system_attrs():
    st = classify("ALTER SYSTEM SET sec_protocol_error_further_action = '(DROP,3)' SCOPE=BOTH SID='*'")
    assert st.attrs["parameter"] == "sec_protocol_error_further_action"
    assert st.attrs["value"] == "'(DROP,3)'"
    assert st.attrs["scope"] == "BOTH" and st.attrs["sid"] == "*"


def test_grant_parse():
    st = classify('GRANT SELECT ANY TABLE, CREATE SESSION TO "APP", rpt WITH ADMIN OPTION')
    assert st.attrs["privileges"] == ["SELECT ANY TABLE", "CREATE SESSION"]
    assert st.attrs["grantees"] == ["APP", "RPT"]
    assert "ADMIN" in st.attrs["options"]
    st2 = classify("revoke execute on sys.utl_file from public")
    assert st2.attrs["object"] == "SYS.UTL_FILE" and st2.attrs["grantees"] == ["PUBLIC"]


def test_canonical_form_ignores_whitespace_case_comments():
    a = "REVOKE EXECUTE ON SYS.UTL_FILE FROM PUBLIC;"
    b = "-- fix\n  revoke   execute on \"SYS\".utl_file\n from public ;"
    assert canonicalize(a) == canonicalize(b)
    assert canonicalize("ALTER SYSTEM SET x='abc'") != canonicalize("ALTER SYSTEM SET x='ABC'")
