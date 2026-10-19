"""Thin python-oracledb wrapper (thin mode by default).

Least-privilege connection roles (paper Section IV.A):
  * audit / context user  -- SELECT_CATALOG_ROLE (+ read-only AWR access if licensed)
  * sandbox admin user    -- common user able to CREATE/ALTER/DROP PLUGGABLE DATABASE
  * apply user            -- only used for AUTO-APPLY, only when apply.enabled=true
"""

from __future__ import annotations

import re
from typing import Any

from ..verify.sandbox import ExecResult
from ..verify.sqltools import Statement

_CONTAINER = re.compile(r"^[A-Za-z][A-Za-z0-9_$#]{0,127}$")


def quote_container(name: str) -> str:
    if name.upper() == "CDB$ROOT":
        return "CDB$ROOT"
    if not _CONTAINER.match(name):
        raise ValueError(f"refusing suspicious container name {name!r}")
    return name.upper()


class OracleClient:
    def __init__(self, dsn: str, user: str, password: str, sysdba: bool = False, thick_lib_dir: str | None = None):
        try:
            import oracledb  # type: ignore
        except ImportError as e:  # pragma: no cover
            raise RuntimeError("python-oracledb is required: pip install 'oracle-remediate[oracle]'") from e
        self._oracledb = oracledb
        if thick_lib_dir:
            oracledb.init_oracle_client(lib_dir=thick_lib_dir)
        kwargs: dict[str, Any] = {"user": user, "password": password, "dsn": dsn}
        if sysdba:
            kwargs["mode"] = oracledb.AUTH_MODE_SYSDBA
        self.conn = oracledb.connect(**kwargs)
        self.current_container: str | None = None
        with self.conn.cursor() as cur:
            # deterministic numeric parsing for invariants using TO_NUMBER on dictionary strings
            cur.execute("ALTER SESSION SET NLS_NUMERIC_CHARACTERS = '.,'")

    def set_container(self, name: str) -> None:
        q = quote_container(name)
        if q == self.current_container:
            return
        with self.conn.cursor() as cur:
            cur.execute(f"ALTER SESSION SET CONTAINER = {q}")
        self.current_container = q

    def query(self, sql: str, binds: dict | None = None, max_rows: int | None = None) -> list[tuple]:
        with self.conn.cursor() as cur:
            cur.execute(sql.strip().rstrip(";"), binds or {})
            rows = cur.fetchmany(max_rows) if max_rows else cur.fetchall()
        return [tuple(r) for r in rows]

    def query_with_columns(self, sql: str, binds: dict | None = None) -> tuple[list[str], list[tuple]]:
        with self.conn.cursor() as cur:
            cur.execute(sql.strip().rstrip(";"), binds or {})
            cols = [d[0] for d in cur.description]
            return cols, [tuple(r) for r in cur.fetchall()]

    def try_query(self, sql: str, binds: dict | None = None, max_rows: int | None = None) -> dict[str, Any]:
        try:
            return {"rows": self.query(sql, binds, max_rows)}
        except Exception as e:  # noqa: BLE001 - surface ORA- errors as context, never crash assembly
            return {"error": str(e).splitlines()[0]}

    def execute_statements(self, statements: list[Statement]) -> ExecResult:
        res = ExecResult()
        for st in statements:
            if st.kind in ("PLSQL_BLOCK", "HOST", "ORA_SET", "ORA_UNSET"):
                res.ok = False
                res.errors.append(f"refusing to execute {st.kind} through the SQL executor")
                continue
            try:
                with self.conn.cursor() as cur:
                    cur.execute(st.text.strip().rstrip(";"))
                res.executed += 1
            except Exception as e:  # noqa: BLE001
                res.ok = False
                res.errors.append(f"{st.kind}: {str(e).splitlines()[0]}")
        return res

    def close(self) -> None:
        try:
            self.conn.close()
        except Exception:  # noqa: BLE001
            pass
