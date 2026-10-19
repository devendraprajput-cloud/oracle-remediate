# Benchmark (paper Section IV.C)

The paper's benchmark is a reference Oracle 19c CDB seeded with induced violations,
tested on three topology profiles, shipped with deterministic seed scripts.

| Profile | How to run | Notes |
|---|---|---|
| `single` | Docker (`docker/docker-compose.yml`) + `seed/` | fully reproducible on one host |
| `rac2` | your 2-node RAC lab + `seed/` | RAC cannot be containerised on one host |
| `exadata` | Exadata / lab with ASM + Data Guard + `seed/` | thin clones via `SNAPSHOT COPY` |
| simulated (all three) | `orarem demo --topology single|rac2|exadata` | offline simulator, no Oracle needed |

## Seed scripts

* `seed/00_audit_user.sql` -- least-privilege common users for the audit and sandbox roles
* `seed/01_seed_violations.sql` -- schemas, profiles, privileges, dependent code and a public DB link
* `seed/02_static_params.sql` -- SPFILE-only parameter violations (restart afterwards)
* `maintenance/cleanup.sql` -- removes the benchmark objects

All scripts are for **disposable test databases only**. The passwords inside them are
throw-away values for the benchmark container.

## Reproducing the evaluation

```bash
orarem --config benchmark/topologies/single.yaml audit --out findings.csv
for i in 1 2 3 4 5; do       # paper: five independent runs, 95% CI
  orarem --config config/local.yaml remediate --findings findings.csv --eval --out runs/opus47-$i
done
orarem eval report runs/opus47-*/run-*            # Pass@1/3/5, safety, rollback fidelity + CI
orarem --config config/local.yaml eval ablation --findings findings.csv   # RQ3
```

Coverage: the catalog currently contains 73 of the 92 controls (see
`orarem catalog validate`). Extend `controls/catalog.yaml` from your licensed CIS
v2.0.0 PDF before claiming full-benchmark results.
