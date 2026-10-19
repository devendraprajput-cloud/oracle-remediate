"""Live-database checks: every generated invariant and snapshot query must execute.

Skipped unless ORAREM_TEST_DSN / ORAREM_TEST_USER / ORAREM_TEST_PASSWORD are set.
Run against a disposable database (CI uses Oracle Database Free; run it against a
19c test CDB as well before relying on the catalog).
"""

import os
from pathlib import Path

import pytest

pytestmark = pytest.mark.oracle
ROOT = Path(__file__).resolve().parents[1]
NEED = ("ORAREM_TEST_DSN", "ORAREM_TEST_USER", "ORAREM_TEST_PASSWORD")


@pytest.fixture(scope="module")
def client():
    if not all(os.environ.get(k) for k in NEED):
        pytest.skip("live Oracle not configured")
    from oracle_remediate.db.oracle import OracleClient
    c = OracleClient(*(os.environ[k] for k in NEED))
    yield c
    c.close()


def test_invariants_execute(client, catalog):
    failures = []
    for c in catalog:
        sql = c.invariant()
        if not sql:
            continue
        try:
            client.query(sql)
        except Exception as e:  # noqa: BLE001
            failures.append(f"{c.id}: {str(e).splitlines()[0]}")
    assert not failures, "\n".join(failures)


def test_snapshot_views_execute(client):
    from oracle_remediate.db.shadow_pdb import load_snapshot_views
    failures = []
    for name, sql in load_snapshot_views(ROOT / "config" / "snapshot_views.yaml").items():
        try:
            client.query_with_columns(sql)
        except Exception as e:  # noqa: BLE001
            failures.append(f"{name}: {str(e).splitlines()[0]}")
    assert not failures, "\n".join(failures)
