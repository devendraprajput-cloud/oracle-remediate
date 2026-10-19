-- Remove the benchmark objects (disposable benchmark CDB only). Run as SYSDBA in CDB$ROOT.
WHENEVER SQLERROR CONTINUE
DEFINE pdb_name = SALES_PDB
ALTER SESSION SET CONTAINER = &pdb_name;
DROP PUBLIC DATABASE LINK remote_sales;
DROP USER app_owner CASCADE;
DROP USER reporting CASCADE;
DROP USER monitor_svc CASCADE;
DROP USER sales_ro CASCADE;
DROP USER ops$batch CASCADE;
DROP PROFILE app_profile CASCADE;
EXIT
