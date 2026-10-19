-- Least-privilege common users for ORACLE-REMEDIATE (paper Section IV.A).
-- Run as SYSDBA in CDB$ROOT of the TEST/benchmark CDB. Review before using elsewhere.
WHENEVER SQLERROR CONTINUE
DEFINE audit_pwd   = "Orarem_Audit_2026#"
DEFINE sandbox_pwd = "Orarem_Sandbox_2026#"

-- Audit / context user: read-only dictionary access in every container
CREATE USER c##orarem_audit IDENTIFIED BY "&audit_pwd" CONTAINER=ALL;
GRANT CREATE SESSION, SET CONTAINER TO c##orarem_audit CONTAINER=ALL;
GRANT SELECT_CATALOG_ROLE TO c##orarem_audit CONTAINER=ALL;
-- Only if the Oracle Diagnostics Pack is licensed and context.awr.enabled is true:
-- GRANT SELECT ON dba_hist_sqlstat TO c##orarem_audit CONTAINER=ALL; (and dba_hist_snapshot, dba_hist_sqltext)

-- Sandbox administrator: creates and drops shadow PDBs
CREATE USER c##orarem_sandbox IDENTIFIED BY "&sandbox_pwd" CONTAINER=ALL;
GRANT CREATE SESSION, SET CONTAINER, CREATE PLUGGABLE DATABASE TO c##orarem_sandbox CONTAINER=ALL;
-- Executing candidate remediations inside the shadow PDB needs the privileges the
-- remediations use (GRANT/REVOKE, ALTER SYSTEM, ALTER PROFILE, AUDIT_ADMIN ...).
-- On a disposable benchmark CDB the simplest option is:
GRANT DBA, AUDIT_ADMIN TO c##orarem_sandbox CONTAINER=ALL;
EXIT
