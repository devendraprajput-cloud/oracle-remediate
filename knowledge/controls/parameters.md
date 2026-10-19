controls: ch2.audit_sys_operations, ch2.global_names, ch2.os_roles, ch2.remote_listener, ch2.remote_login_passwordfile, ch2.remote_os_roles, ch2.sec_max_failed_login_attempts, ch2.sec_protocol_error_further_action, ch2.sec_protocol_error_trace_action, ch2.sec_return_server_release_banner, ch2.sql92_security, ch2.resource_limit
# Initialisation parameters in CDB, RAC and Data Guard environments

## Static versus dynamic

V$PARAMETER.ISSYS_MODIFIABLE shows whether ALTER SYSTEM can change a
parameter in memory (IMMEDIATE or DEFERRED) or only in the SPFILE (FALSE).
Static parameters need SCOPE=SPFILE and an instance restart; on RAC this is
done as a rolling restart.

## PDB versus CDB scope

V$PARAMETER.ISPDB_MODIFIABLE shows whether a PDB can set its own value. CDB
level parameters can only be changed in the root, so they cannot be verified in
a cloned PDB; they need a CDB-level sandbox.

## RAC

Use SID='*' so that every instance receives the same SPFILE value. RAC
databases normally register services with the SCAN listener through
REMOTE_LISTENER, so an empty REMOTE_LISTENER is usually an approved exception
on RAC.

## Data Guard

Redo transport between primary and standby authenticates with the password
file unless SSL authentication is configured, so REMOTE_LOGIN_PASSWORDFILE set
to NONE breaks redo transport. Check GV$DATAGUARD_CONFIG before changing it.
