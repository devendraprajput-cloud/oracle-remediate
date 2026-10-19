controls: none
# Multitenant, RAC and Exadata context for remediation

* Users, roles, profiles and grants can be common (created in the root with
  CONTAINER=ALL, names prefixed C## by default) or local to one PDB. A local
  remediation is executed inside the affected PDB.
* V$CONTAINERS lists open containers and their CON_IDs; CDB_* views report
  across containers when queried from the root.
* GV$INSTANCE lists RAC instances; SPFILE changes use SID='*'.
* V$CELL lists Exadata storage cells; snapshot-copy PDB clones depend on the
  storage type (Exadata sparse grid disks or ACFS) and release-specific
  prerequisites.
* CREATE PLUGGABLE DATABASE ... FROM <pdb> clones a PDB; with SNAPSHOT COPY it
  creates a thin clone where supported. Clones are the sandbox for testing a
  remediation and its rollback before production.
