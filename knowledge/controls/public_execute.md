controls: ch6.public_exec_utl_tcp, ch6.public_exec_utl_smtp, ch6.public_exec_utl_mail, ch6.public_exec_utl_http, ch6.public_exec_utl_inaddr, ch6.public_exec_dbms_ldap, ch6.public_exec_utl_file, ch6.public_exec_dbms_lob, ch6.public_exec_dbms_advisor, ch6.public_exec_dbms_crypto, ch6.public_exec_dbms_random, ch6.public_exec_dbms_java, ch6.public_exec_dbms_java_test, ch6.public_exec_dbms_scheduler, ch6.public_exec_dbms_job, ch6.public_exec_dbms_sql, ch6.public_exec_dbms_xmlgen, ch6.public_exec_dbms_backup_restore
# Revoking EXECUTE on SYS packages from PUBLIC

Network, file, scheduler and dynamic-SQL packages granted to PUBLIC let any
account reach the network, the file system or build dynamic SQL. Hardening
guides recommend revoking EXECUTE from PUBLIC and granting it only to the
schemas that need it.

## Dependency risk

Stored PL/SQL that runs with definer's rights resolves privileges from direct
grants (or PUBLIC); privileges received through roles are not used. If an
application schema compiled code against a package only because PUBLIC had
EXECUTE, revoking the PUBLIC grant invalidates that code. Before revoking,
look up dependents in DBA_DEPENDENCIES (the referenced owner may appear as
SYS or as PUBLIC when a public synonym was used) and grant EXECUTE directly
to each dependent schema first.

## Multitenant

In a CDB, a grant made commonly in the root (CONTAINER=ALL) has to be
revoked commonly; a local grant inside a PDB is revoked inside that PDB.

## Rollback

The inverse of `REVOKE EXECUTE ON SYS.<pkg> FROM PUBLIC` is
`GRANT EXECUTE ON SYS.<pkg> TO PUBLIC`, and any direct grants added by the
remediation are revoked again.
