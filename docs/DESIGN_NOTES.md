# Design notes, deviations and known gaps

Every place where this implementation differs from, or adds to, the paper is listed
here so that results can be reported accurately.

## D1 -- `strict_auto_apply` (default on)

With the paper's weights a candidate that **did not fix the finding** can be auto-applied:

| A | L1 | L2 | L3 | L_RB | R | C |
|---|---|---|---|---|---|---|
| 1.0 | 1 | **0** | 1 | 1 | low (1.0) | 0.40 + 0.30·(2/3) + 0.20 + 0.10 = **0.90** >= 0.85 |

The hard floors only cover L3 and L_RB. `decision.strict_auto_apply: true` additionally
requires L1 = L2 = 1 for AUTO-APPLY (otherwise MANUAL-REVIEW). Set it to `false` to
reproduce the paper exactly; `tests/test_scoring.py` demonstrates both.

## D2 -- Layer-1 failures are never executed

Listing 2 executes the remediation in the sandbox regardless of Layer 1, and the
decision relies on the hard floors (L3, L_RB). Those floors only see the data
dictionary. A candidate that adds `TRUNCATE TABLE app.orders` to a correct fix changes
no dictionary view in the snapshot, so L2 = L3 = L_RB = 1 and, with A = 1 and low risk,
C = 0.40 + 0.30·(2/3) + 0.20 + 0.10 = 0.90 -> AUTO-APPLY with data loss. (A `DROP USER`
would usually be caught by the round trip, because the rollback cannot recreate it.)

Here, a Layer-1 failure is recorded and nothing is executed; L2/L3/L_RB are recorded as
0 ("not executed"), so the hard floor rejects it. Expected deltas are derived only from
whitelisted statement kinds. (`verifier.never_execute_l1_failures`.)

## D3 -- Sampling temperature is provider-dependent

Verified October 2026:

* Anthropic: non-default `temperature`/`top_p`/`top_k` return HTTP 400 on Claude Opus 4.7
  and later (`claude-opus-4-7` is the API id).
* OpenAI: GPT-5 reasoning models accept only the default temperature (1).
* Self-hosted Llama-3.3-70B (vLLM/Ollama) honours `temperature`.

`llm.temperature_policy: auto` omits the parameter for documented models and retries
without it on a sampling-parameter 400. Each run records `temperature_requested` and
`temperature_applied`; report T=0.3 only for runs where it was applied. A temperature
sweep (paper Fig. 2) is only meaningful on backends that honour the parameter.

## D4 -- k versus n

The paper uses k=5 for self-consistency and n=10 for agreement / Pass@k. Normal runs
draw `self_consistency.k` (5) samples; `--eval` draws `evaluation.n` (10) samples and
verifies every distinct candidate to obtain c for Pass@k.

## D5 -- Parser

Layer 1 needs statement kinds plus a few attributes (privileges, grantees, parameter
names, ORA keys), which a small lexer provides without a generated ANTLR parser.
Anonymous PL/SQL, `EXECUTE`/`CALL` and host commands are classified as forbidden because
dynamic SQL cannot be verified statically. To use ANTLR4 (grammars-v4 `PlSqlParser.g4`),
replace `verify/sqltools.parse_script` with an adapter that returns the same `Statement`
objects.

## D6 -- Threshold calibration wording

III.D-3 defines tau_review as "the lowest value at which the manual-review queue contains
no remediation that would have been silently incorrect had it been auto-applied". The
literal reading is implemented (no incorrect item inside [tau_review, tau_auto)). Other
readings are possible; state the one you use.

## D7 -- AWR licensing

DBA_HIST_* views require the Oracle Diagnostics Pack licence. AWR top-SQL is off by
default (`context.awr.enabled`) and also gated on CONTROL_MANAGEMENT_PACK_ACCESS; GV$SQL
(cursor cache) is used otherwise.

## D8 -- Layer-1 extensions

Beyond the paper's whitelist and FORBIDDEN set: `ALTER SYSTEM` must SET/RESET the
control's own parameter (other `ALTER SYSTEM` forms are forbidden); a privilege-escalation
guard rejects remediation grants of ANY privileges, DBA/SYS* roles, ADMIN/GRANT OPTION
or grants to PUBLIC; `ALTER USER ... IDENTIFIED` is rejected as non-invertible; every
`GRANT` in a rollback must restore a privilege the remediation revoked. These narrow,
but do not close, the "masked privilege escalation" limitation in Section V.

## D9 -- Snapshot and delta

Snapshots select only stable columns (`config/snapshot_views.yaml`), so normalisation
happens by construction; diffs are set differences of row tuples (DeepDiff is not
required). Object validity is captured as counts per owner/type/status
(`DBA_OBJECTS_STATUS`) to catch invalidation cascades. The unified audit trail is not
snapshotted because executing the remediation is itself audited. `SYS.LINK$` hashes are
optional (needs SELECT on SYS.LINK$).

## D10 -- CDB scope

CDB-level parameters and *common* grants (e.g. Oracle's default EXECUTE grants to PUBLIC,
which are revoked from CDB$ROOT with `CONTAINER=ALL`) cannot be verified in a cloned PDB.
They use `sandbox.cdb_sandbox` (a disposable CDB). If none is configured the verifier
records L3 = 0 with the reason, and the hard floor rejects -- an explicit failure rather
than a silent pass.

## D11 -- Static parameters

A static parameter changed with `SCOPE=SPFILE` does not change V$PARAMETER until restart,
so L2 cannot confirm the fix in a sandbox without restarting it. These findings are routed
to MANUAL-REVIEW and count as not passing in Pass@k. A restartable CDB sandbox would allow
verification; this is not automated.

## D12 -- Offline simulator and mock LLM

`sim/` models the dictionary state touched by the catalog and `llm/mock.py` is a
rule-based stand-in for a model. They exist so the framework, tests and CI run without
Oracle or API keys. **Numbers produced with the mock backend say nothing about LLM
performance and must not be reported as results.**

## D13 -- Policy-context ablation

`context.policy: false` removes policy text from the prompt only; approved exceptions and
review-only overrides are still enforced by the decision layer.

## D14 -- Catalog coverage

The reference catalog has 73 controls (target 92). `cis_id` is set only for 4.7, 2.2.7
and 2.2.11, which the paper names. Before claiming full-benchmark results, map and add
the remaining controls from the licensed CIS v2.0.0 document and validate every
invariant on a 19c test CDB (`pytest -m oracle`).

## D15 -- Pass@k success criterion

A sample counts toward c when L1 = L2 = L3 = 1 ("passes the verifier and produces the
correct invariant restoration"). Rollback success is reported separately (RQ4).

## Known gaps

* Shadow PDBs open on the local RAC instance only; instance-specific (`SID=`) behaviour
  is checked through context, not executed on every node.
* The `extproc` listener control and other nested listener edits are manual.
* Prose baselines (CIS text, DBSAT recommendations) require human annotation.
* Snapshot-copy prerequisites differ by storage and release; the clone statement is a
  configurable template and must be validated on your platform.
