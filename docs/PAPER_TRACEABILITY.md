# Paper-to-code traceability

Status: **Implemented** = behaviour as described; **Extended** = implemented plus documented
safeguards; **Partial** = framework support exists but needs your environment or licensed
content; **Deferred** = listed by the paper as future work.

| Paper element | Section | Code | Status |
|---|---|---|---|
| Finding schema (control id, title, observed, expected, containers, grantees, raw SQL) | III.A | `models.Finding`, `ingestion/findings.py` | Implemented |
| Multiple upstream assessors | III.A | CSV / JSONL / YAML column mapping | Implemented |
| Topology context (GV$INSTANCE, V$CONTAINERS, GV$DATAGUARD_CONFIG, DBA_REGISTRY) | III.B | `context/sources.py:OracleContextSource.topology` (+ V$DATABASE, V$CELL) | Implemented |
| Dependency context (DBA_OBJECTS, DBA_DEPENDENCIES, CDB_TAB_PRIVS, 24 h AWR) | III.B | `OracleContextSource.dependencies` | Extended (AWR licence-gated, GV$SQL default) |
| Documentation context via Oracle 23ai AI Vector Search | III.B | `rag/store.py:Oracle23aiVectorStore`, `rag/retriever.py` | Implemented (corpus: bring your licensed copies) |
| Context-augmented query (control id + keywords + deviation) | III.B | `rag/retriever.py:build_query` | Implemented |
| Policy context (exceptions, change window, service accounts) | III.B | `scoring/policy.py:PolicyContext` | Implemented |
| Structured prompt + strict output schema | III.C | `prompts/`, `llm/prompt.py` | Implemented |
| k=5 self-consistency, T=0.3, plurality | III.C | `llm/generator.py` | Extended (temperature applied/recorded per provider, see D3) |
| Claude Opus 4.7 / GPT-5-class / Llama-3.3-70B | III.C | `llm/backends.py` | Implemented |
| LangChain orchestration | IV.A, Table II | `llm/backends.py:LangChainBackend` (optional) | Implemented (optional) |
| Agreement A over canonicalised AST | III.D-1 | `verify/sqltools.canonicalize`, generator | Implemented |
| V = (L1+L2+L3)/3, L_RB, R mapping, weights | III.D-1 | `scoring/confidence.py` | Implemented |
| Thresholds 0.85 / 0.55, hard floors L3/L_RB, review-only override | III.D-2 | `scoring/policy.py:decide` | Extended (`strict_auto_apply`, D1) |
| Threshold calibration on 20 held-out controls | III.D-3 | `eval/metrics.calibrate_thresholds`, `orarem eval calibrate` | Implemented (needs labels) |
| Layer 1 static AST whitelist + FORBIDDEN (Listing 1) | III.E-1 | `verify/static_check.py` | Extended (D2, D8) |
| Layer 2 invariants phi_c + sampled non-interference | III.E-2 | `controls.py`, `verify/verifier.py` | Implemented |
| Layer 3 shadow-PDB bisimulation, expected delta from AST | III.E-3 | `db/shadow_pdb.py`, `verify/bisimulation.py` | Implemented |
| Round-trip rollback S0 -> S1 -> S2, normalisation | III.F | `verify/verifier.py` | Implemented |
| One-way controls routed to manual review | III.F, V | `Control.rollback_possible`, `pipeline.py` | Implemented |
| Control 4.7 worked example | III.G | `tests/test_pipeline.py::test_paper_example_control_4_7...` | Reproduced (simulator) |
| Audit framework Bash + SQL*Plus + Python | Table II | `audit/run_audit.sh`, `orarem audit` | Implemented |
| Sandbox alt.: Oracle XE/Free in Docker | Table II | `docker/`, CI `oracle-integration` job | Implemented |
| DeepDiff over dictionary snapshots | Table II | set difference over normalised row tuples (`bisimulation.diff`) | Equivalent (D9) |
| ANTLR4 PL/SQL grammar | Table II | dependency-free lexer (`sqltools.py`) | Substituted (D5) |
| 92-control benchmark, 3 topologies, Docker | IV.C | `controls/catalog.yaml` (73), `benchmark/`, simulator profiles | Partial (D14) |
| Baselines: CIS text, DBSAT, zero-shot, full | IV.D | `eval/ablation.py` (zero-shot, full); prose baselines by annotation | Partial |
| Pass@k (Chen et al.), safety FN rate, rollback rate, tokens, time, USD | IV.E | `eval/metrics.py`, run summary | Implemented |
| Cohen's kappa, 95% CI over 5 runs | IV.E/F | `eval/metrics.py` | Implemented |
| RQ3 context ablation | IV.B | `orarem eval ablation` | Implemented |
| Swingbench / HammerDB performance study | VI.A | -- | Deferred (paper future work) |
| CDC continuous compliance, cross-DB ports, formal proofs, CVSS scoring | VI | -- | Deferred (paper future work) |
