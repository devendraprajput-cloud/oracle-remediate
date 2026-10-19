controls: ch3.failed_login_attempts, ch3.password_lock_time, ch3.password_life_time, ch3.password_reuse_max, ch3.password_reuse_time, ch3.password_grace_time, ch3.password_verify_function, ch3.sessions_per_user, ch3.inactive_account_time, ch4.users_not_default_profile
# Profile password and resource limits

Profiles carry password limits (FAILED_LOGIN_ATTEMPTS, PASSWORD_LIFE_TIME,
PASSWORD_REUSE_TIME, PASSWORD_REUSE_MAX, PASSWORD_LOCK_TIME,
PASSWORD_GRACE_TIME, PASSWORD_VERIFY_FUNCTION, INACTIVE_ACCOUNT_TIME) and
kernel limits (SESSIONS_PER_USER and others).

## DEFAULT inheritance

A limit set to DEFAULT in any profile inherits the value of the DEFAULT
profile. Fixing the DEFAULT profile therefore fixes every profile that
inherits; an explicit value in another profile overrides it. A rollback must
restore the literal value that was there before (including the word DEFAULT),
not the effective value, otherwise the round trip is not exact.

## Kernel limits

Kernel limits such as SESSIONS_PER_USER are only enforced when the
RESOURCE_LIMIT parameter is TRUE. Connection-pooled application accounts often
need a dedicated profile with a higher session limit.

## Password verify function

Oracle supplies verify functions created by the utlpwdmg.sql script (for
example ORA12C_STRONG_VERIFY_FUNCTION in recent releases); confirm the function
exists before assigning it to a profile.
