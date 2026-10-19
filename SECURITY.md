# Security policy

## Responsible use

ORACLE-REMEDIATE executes model-generated SQL. Treat it accordingly:

* Start with a disposable test CDB (see `benchmark/`). Never point the sandbox
  administrator at a production CDB without understanding the clone's storage and I/O cost.
* Keep `apply.enabled: false` until you have reviewed MANUAL-REVIEW and AUTO-APPLY
  outputs over several runs and calibrated thresholds on your own held-out controls.
* Use least-privilege database users (`benchmark/seed/00_audit_user.sql`) and
  credentials from environment variables or an Oracle wallet. Never commit `.env`.
* Findings, context and prompts may contain schema names, hostnames and account names.
  Check your organisation's policy before sending them to a hosted LLM; a self-hosted
  model (`openai_compatible`) keeps data on your network.
* Do not commit licensed material (CIS benchmark text, My Oracle Support notes).

## Reporting a vulnerability

Please report security issues privately through GitHub Security Advisories for this
repository rather than in public issues.
