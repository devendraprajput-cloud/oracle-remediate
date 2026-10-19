-- =====================================================================================
-- ORACLE-REMEDIATE benchmark seed: induce CIS violations in a DISPOSABLE test CDB.
-- NEVER RUN ON A PRODUCTION OR SHARED DATABASE.
--
-- Run as SYSDBA in CDB$ROOT, e.g. automatically by the oracle/docker-images container
-- (mounted into /opt/oracle/scripts/setup) or manually:
--     sqlplus / as sysdba @01_seed_violations.sql
-- The passwords below are throw-away values for the disposable benchmark container only.
--
-- Mirrors src/oracle_remediate/sim/scenarios.py so simulator and real runs are comparable.
-- Several violations (e.g. EXECUTE on UTL_* granted to PUBLIC) already exist on a default
-- install; verify with `orarem audit` after seeding.
-- =====================================================================================
WHENEVER SQLERROR CONTINUE
SET ECHO ON
DEFINE pdb_name     = SALES_PDB
DEFINE loopback_tns = 'localhost:1521/SALES_PDB'
DEFINE bench_pwd    = "Orarem_Bench_2026#"

-- ------------------------------------------------------------- CDB-level parameters (dynamic)
ALTER SYSTEM SET sec_protocol_error_further_action = 'CONTINUE' SCOPE=BOTH;
ALTER SYSTEM SET sec_protocol_error_trace_action  = 'TRACE'    SCOPE=BOTH;
ALTER SYSTEM SET resource_limit = FALSE SCOPE=BOTH;
ALTER SYSTEM SET global_names   = FALSE SCOPE=BOTH;

ALTER SESSION SET CONTAINER = &pdb_name;

-- ------------------------------------------------------------- application schemas
CREATE USER app_owner   IDENTIFIED BY "&bench_pwd";
CREATE USER reporting   IDENTIFIED BY "&bench_pwd";
CREATE USER monitor_svc IDENTIFIED BY "&bench_pwd";
CREATE USER sales_ro    IDENTIFIED BY "&bench_pwd";
CREATE USER ops$batch   IDENTIFIED EXTERNALLY;
ALTER USER app_owner QUOTA UNLIMITED ON users;
ALTER USER sales_ro  QUOTA UNLIMITED ON users;
GRANT CREATE SESSION, CREATE TABLE, CREATE VIEW, CREATE PROCEDURE TO app_owner;
GRANT CREATE SESSION, CREATE TABLE TO sales_ro;
GRANT CREATE SESSION TO monitor_svc;

CREATE TABLE sales_ro.orders (id NUMBER PRIMARY KEY, amount NUMBER);
CREATE TABLE app_owner.orders (id NUMBER PRIMARY KEY, amount NUMBER);

-- ------------------------------------------------------------- profiles (ch3, ch4)
ALTER PROFILE DEFAULT LIMIT
  FAILED_LOGIN_ATTEMPTS 10  PASSWORD_LIFE_TIME 180  PASSWORD_GRACE_TIME 7
  PASSWORD_VERIFY_FUNCTION NULL  SESSIONS_PER_USER UNLIMITED  INACTIVE_ACCOUNT_TIME UNLIMITED;
CREATE PROFILE app_profile LIMIT PASSWORD_LIFE_TIME UNLIMITED SESSIONS_PER_USER 200;
ALTER USER app_owner   PROFILE app_profile;
ALTER USER monitor_svc PROFILE app_profile;
-- reporting deliberately stays on DEFAULT (ch4.users_not_default_profile)

-- ------------------------------------------------------------- privileges (ch6)
GRANT SELECT ANY TABLE TO app_owner;
GRANT DBA TO app_owner;
GRANT SELECT ANY DICTIONARY TO reporting;
GRANT CREATE SESSION TO reporting WITH ADMIN OPTION;
GRANT SELECT ON sys.user$ TO reporting;
GRANT SELECT_CATALOG_ROLE TO monitor_svc;

-- ------------------------------------------------------------- dependency: code relying on PUBLIC EXECUTE
CREATE OR REPLACE PACKAGE app_owner.file_logger AS
  PROCEDURE log_line(p_dir VARCHAR2, p_file VARCHAR2, p_text VARCHAR2);
END file_logger;
/
CREATE OR REPLACE PACKAGE BODY app_owner.file_logger AS
  PROCEDURE log_line(p_dir VARCHAR2, p_file VARCHAR2, p_text VARCHAR2) IS
    f UTL_FILE.FILE_TYPE;
  BEGIN
    f := UTL_FILE.FOPEN(p_dir, p_file, 'a');
    UTL_FILE.PUT_LINE(f, p_text);
    UTL_FILE.FCLOSE(f);
  END log_line;
END file_logger;
/

-- ------------------------------------------------------------- public database link + dependents (ch4 / paper III.G)
CREATE PUBLIC DATABASE LINK remote_sales CONNECT TO sales_ro IDENTIFIED BY "&bench_pwd" USING '&loopback_tns';
CREATE OR REPLACE VIEW app_owner.v_remote_orders AS SELECT id, amount FROM sales_ro.orders@remote_sales;
CREATE OR REPLACE VIEW app_owner.v_remote_stock  AS SELECT COUNT(*) AS n FROM sales_ro.orders@remote_sales;

SELECT owner, object_name, object_type, status FROM dba_objects WHERE owner = 'APP_OWNER' ORDER BY 2;
EXIT
