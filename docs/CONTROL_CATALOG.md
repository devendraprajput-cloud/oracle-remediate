# Control catalog

`controls/catalog.yaml` is the single source of truth for each control's invariant
(phi_c), its Layer-1 class and its scope flags.

## Fields

| Field | Meaning |
|---|---|
| `id` | stable framework id, e.g. `ch6.public_exec_utl_file` |
| `cis_id` | CIS v2.0.0 recommendation number (fill from your licensed PDF) |
| `provenance` | `paper`, `cis-19c-family` or `example` (see header of the file) |
| `control_class` | `ch1_patch`, `ch2_param`, `ch2_file`, `ch3_prof`, `ch4_user`, `ch5_audit`, `ch6_priv` -- selects the Layer-1 whitelist |
| `kind` + `params` | typed invariant template (below) |
| `scope` | `auto`, `pdb`, `cdb`, `file` |
| `rollback_possible` | false -> out of automated scope, routed to MANUAL-REVIEW |
| `review_only` | caps AUTO-APPLY at MANUAL-REVIEW (SYSDBA/SYSTEM/audit-class controls) |
| `requires_restart` | fallback when the live ISSYS_MODIFIABLE is unavailable |
| `expected_tables_extra` | additional views Layer 3 may see change |
| `invariant_sql` | with `kind: custom`, a raw SQL predicate (rows iff non-compliant) |

## Kinds

| kind | params | invariant source |
|---|---|---|
| `parameter` | `name`, `op` (eq, empty, le, ge), `expected` | GV$PARAMETER |
| `ora_file` | `file`, `key` (may contain `{listener}`), `op` (eq, present, absent_substring) | parsed .ora file |
| `profile_limit` | `resource`, `op` (le, ge, not_null), `value` | DBA_PROFILES with DEFAULT resolution |
| `public_execute` | `object`, `owner` | DBA_TAB_PRIVS |
| `sys_priv` | `privileges` or `pattern` | DBA_SYS_PRIVS, non-Oracle-maintained grantees |
| `role_grant` | `roles` | DBA_ROLE_PRIVS |
| `admin_option` | -- | DBA_SYS_PRIVS.ADMIN_OPTION |
| `object_access` | `objects`, `owner` | DBA_TAB_PRIVS |
| `no_public_db_links` | -- | DBA_DB_LINKS |
| `users_default_profile`, `default_passwords`, `external_auth` | -- | DBA_USERS (+ DBA_USERS_WITH_DEFPWD) |
| `audit_action` | `option`, `option_type` | AUDIT_UNIFIED_POLICIES + AUDIT_UNIFIED_ENABLED_POLICIES |
| `manual` | -- | none (manual review) |
| `custom` | `invariant_sql` | as given |

"Non-Oracle-maintained" uses DBA_USERS.ORACLE_MAINTAINED and DBA_ROLES.ORACLE_MAINTAINED.

## Semantics to confirm against CIS v2.0.0

* Profile lower bounds (`ge`) treat `UNLIMITED` as compliant. For PASSWORD_REUSE_MAX /
  PASSWORD_REUSE_TIME, Oracle's interaction rule (both UNLIMITED means reuse is allowed)
  is not modelled; check the benchmark's audit query.
* Profile checks cover every profile, not only profiles in use.
* The unified-audit predicate requires a policy enabled for all users, for success and
  failure, with no condition. Confirm column values (ENABLED_OPTION / ENTITY_NAME) on
  your release with `pytest -m oracle`.

## Adding a control

1. Add the YAML entry (prefer a typed `kind`; use `custom` otherwise).
2. `orarem catalog show <id>` to inspect the generated SQL.
3. Add the violation to `benchmark/seed/01_seed_violations.sql` and, if the kind is new,
   to the simulator (`sim/simulator.py:evaluate`) and `sim/scenarios.py`.
4. `pytest` and `pytest -m oracle` against a test CDB.
