controls: ch2.sqlnet_encryption_server, ch2.sqlnet_crypto_checksum_server, ch2.listener_admin_restrictions, ch2.listener_secure_control, ch2.listener_no_extproc
# Oracle Net configuration files

## sqlnet.ora

SQLNET.ENCRYPTION_SERVER and SQLNET.CRYPTO_CHECKSUM_SERVER accept REJECTED,
ACCEPTED, REQUESTED or REQUIRED. REQUIRED refuses clients that cannot
negotiate native network encryption or integrity, so confirm client
capabilities first. Choose strong algorithms with
SQLNET.ENCRYPTION_TYPES_SERVER and SQLNET.CRYPTO_CHECKSUM_TYPES_SERVER.

## listener.ora

ADMIN_RESTRICTIONS_<listener>=ON prevents runtime changes to the listener
through lsnrctl SET commands; changes must be made in listener.ora and
reloaded. SECURE_CONTROL_<listener> restricts administrative control to the
listed transports. External procedure (extproc) entries should be removed
unless required; if required, configure them on a dedicated listener.

## Rollback

Edits are reversible by restoring the previous key value (or removing an
added key) and reloading the listener; keep a copy of the original file.
