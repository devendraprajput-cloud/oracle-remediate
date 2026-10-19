# Contributing

1. `pip install -e ".[dev]"`, then `pytest` and `ruff check src tests` must pass.
2. New controls: follow `docs/CONTROL_CATALOG.md`, add a seed violation, and run
   `pytest -m oracle` against a test CDB.
3. Keep verifiers informational: they record outcomes; only `scoring/policy.py` decides.
4. Any behaviour that differs from the paper goes into `docs/DESIGN_NOTES.md`.
5. Do not add licensed CIS or Oracle Support text to the repository.
