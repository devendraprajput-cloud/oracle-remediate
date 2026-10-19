controls: ch5.audit_create_user, ch5.audit_alter_user, ch5.audit_drop_user, ch5.audit_create_role, ch5.audit_grant, ch5.audit_revoke, ch5.audit_create_db_link, ch5.audit_alter_system
# Unified audit policies

A unified audit policy is created with CREATE AUDIT POLICY ... ACTIONS ...,
then enabled with AUDIT POLICY. AUDIT_UNIFIED_POLICIES lists each policy's
audit options and AUDIT_UNIFIED_ENABLED_POLICIES lists how it is enabled
(for all users, by user, except user, success/failure).

## Rollback

The inverse of enabling is NOAUDIT POLICY; a policy must be disabled before
DROP AUDIT POLICY succeeds. Creating a dedicated policy per control keeps the
rollback exact; altering an Oracle-supplied policy is harder to undo.

## Operational impact

Every audited action writes to the unified audit trail in the AUDSYS schema.
Plan tablespace capacity and purge jobs (DBMS_AUDIT_MGMT) before enabling
high-volume actions.
