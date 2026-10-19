-- Static (SPFILE-only) parameter violations. Requires an instance restart afterwards:
--     docker restart <container>      (or SHUTDOWN IMMEDIATE / STARTUP)
-- Disposable benchmark CDB only. Run as SYSDBA in CDB$ROOT.
WHENEVER SQLERROR CONTINUE
ALTER SYSTEM SET audit_sys_operations          = FALSE SCOPE=SPFILE;
ALTER SYSTEM SET sec_max_failed_login_attempts = 10    SCOPE=SPFILE;
ALTER SYSTEM SET sql92_security                = FALSE SCOPE=SPFILE;
ALTER SYSTEM SET remote_login_passwordfile     = EXCLUSIVE SCOPE=SPFILE;
EXIT
