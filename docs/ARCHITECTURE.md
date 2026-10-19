# Architecture

ORACLE-REMEDIATE has five components (paper Section III) plus the confidence scorer
(III.D). The sequence below mirrors Fig. 1 of the paper; module names are in brackets.

```mermaid
sequenceDiagram
    autonumber
    participant DBA as DBA Operator<br/>[cli.py]
    participant AUD as Audit FW<br/>[audit/]
    participant CTX as Context / Topology<br/>[context/, rag/]
    participant LLM as LLM Generator<br/>[llm/]
    participant SV as Safety Verifier<br/>[verify/]
    participant PROD as Prod CDB Target
    participant SB as Shadow Sandbox PDB<br/>[db/shadow_pdb.py]
    participant CS as Confidence Scorer / Decision<br/>[scoring/]

    rect rgb(245,245,245)
    note over DBA,AUD: 1. Audit phase
    DBA->>AUD: orarem audit
    AUD->>PROD: execute catalog invariants phi_c (per container)
    PROD-->>AUD: violating rows
    AUD-->>DBA: findings.csv
    end

    loop 2. for each finding F  [pipeline.py]
        DBA->>CTX: remediate(F)
        CTX->>PROD: GV$INSTANCE, V$CONTAINERS, GV$DATAGUARD_CONFIG, DBA_REGISTRY, V$CELL
        CTX->>PROD: DBA_DEPENDENCIES, DBA_OBJECTS, DBA_TAB_PRIVS, GV$SQL (AWR if licensed)
        CTX->>CTX: RAG retrieval (Oracle 23ai AI Vector Search / in-memory)
        CTX->>LLM: enriched prompt (finding + 4 context classes + strict schema)
        LLM->>LLM: k samples (T=0.3 where the provider allows), plurality vote -> A
        LLM->>SV: candidate {remediation, rollback, risk_level}
        SV->>SV: L1 static AST whitelist
        SV->>PROD: request snapshot clone
        PROD->>SB: CREATE PLUGGABLE DATABASE ... SNAPSHOT COPY | FROM <pdb>
        SV->>SB: L2 invariants pre/post (+ sampled non-interference)
        SV->>SB: L3 apply + dictionary delta vs AST-expected delta
        SV->>SB: round-trip rollback S0 -> S1 -> S2
        SB-->>SV: L2, L3, L_RB outcomes
        SV->>CS: L1, L2, L3, L_RB (informational, never gating)
        LLM->>CS: agreement A, risk R
        CS->>CS: C = 0.40A + 0.30V + 0.20L_RB + 0.10R; hard floors; overrides
        CS-->>DBA: AUTO-APPLY | MANUAL-REVIEW | REJECT (+ scripts, rationale)
    end
```

## Data flow and artefacts

```
findings.csv ──► Finding ──► ContextAssembler ──► GenerationRequest ──► RemediationGenerator
                                                                         │ k (or n) samples
                                                                         ▼
                         Sandbox (shadow PDB | CDB sandbox | ora-file | simulator)
                                   ▲                         │
                    verify_candidate (L1, L2, L3, L_RB) ◄─────┘
                                   │
                         confidence() ─► decide() ─► FindingOutcome ─► runs/run-<ts>/
                                                                         ├── run.json, summary.md, dispositions.csv
                                                                         └── findings/<id>/remediation.sql, rollback.sql,
                                                                             verification.sql, decision.json, rationale.md
```

## Sandbox selection

| Control | Sandbox | Why |
|---|---|---|
| listener.ora / sqlnet.ora | `OraFileSandbox` (temp copies) | host files, edited by `ORA_SET`/`ORA_UNSET` |
| PDB-modifiable parameter, dictionary objects in a PDB | `ShadowPdbSandbox` | clone of the affected PDB |
| CDB-level parameter, common grants (`COMMON='YES'`) | `CdbSandbox` | a PDB cannot change CDB scope |
| none configured / clone failed | `UnavailableSandbox` | records L3 = 0 with the reason -> hard-floor REJECT |
| offline | `SimulatedSandbox` | deep copy of the simulator state |

## Security model

* Three database identities with separate credentials: read-only audit/context user,
  sandbox administrator (shadow PDBs), and an apply user that is only used when
  `apply.enabled: true` **and** `--apply` are both given.
* Credentials come only from environment variables named in the config.
* Model output is data: it is parsed, statically checked and executed only inside a
  sandbox. Layer-1 failures are never executed anywhere.
* All decisions and production actions are written to the run directory
  (`decision.json`, `apply_audit.jsonl`).
