controls: ch6.no_any_privileges, ch6.no_audit_system, ch6.no_alter_system_priv, ch6.no_become_user, ch6.no_exempt_access_policy, ch6.no_exempt_redaction_policy, ch6.no_create_library, ch6.no_admin_option, ch6.no_dba_role, ch6.no_select_catalog_role, ch6.no_execute_catalog_role, ch6.no_access_user_dollar, ch6.no_access_user_history, ch6.no_access_scheduler_credential, ch6.no_access_xs_verifiers
# System privileges, powerful roles and sensitive dictionary tables

ANY privileges, DBA, the catalog roles, BECOME USER, EXEMPT ACCESS POLICY,
EXEMPT REDACTION POLICY and CREATE LIBRARY bypass normal access control.
Grant them only to Oracle-maintained accounts or to explicitly approved
administrators. DBA_USERS.ORACLE_MAINTAINED and DBA_ROLES.ORACLE_MAINTAINED
identify Oracle-supplied accounts and roles.

## Least-privilege replacement

When an application schema holds DBA or ANY privileges, replace them with the
specific object privileges it uses (find them from its SQL in GV$SQL or AWR
and from DBA_DEPENDENCIES) before revoking, and test in a cloned PDB.

## WITH ADMIN OPTION

A grantee with ADMIN OPTION can grant the privilege onward. Removing only the
admin option means revoking the privilege and granting it again without the
option; the rollback grants it back WITH ADMIN OPTION.

## Sensitive tables

SYS.USER$, SYS.USER_HISTORY$, SYS.LINK$, SYS.SCHEDULER$_CREDENTIAL and
SYS.XS$VERIFIERS hold password verifiers or credentials and must not be
readable by application accounts.
