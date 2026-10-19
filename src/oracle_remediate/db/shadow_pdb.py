"""Shadow-PDB sandbox for Layer 3 / round-trip rollback (paper Section III.E-3, IV.A).

Clone statements are *templates in configuration*, because the right clause is
platform specific:

* Exadata / sparse or ACFS storage: ``CREATE PLUGGABLE DATABASE {shadow} FROM {source} SNAPSHOT COPY``
* otherwise: a full (hot) clone, ``CREATE PLUGGABLE DATABASE {shadow} FROM {source}`` plus
  ``FILE_NAME_CONVERT`` if OMF is not used
* clone from a remote CDB to keep clone I/O off production:
  ``... FROM {source}@<dblink>`` executed on a sandbox CDB

Snapshot-copy prerequisites (source open mode, storage type, CLONEDB) vary by
release and platform -- validate the template on your platform first.

CDB-scope parameters cannot be changed from inside a PDB.  Those controls are
verified in :class:`CdbSandbox`, a *disposable* CDB (e.g. the benchmark Docker
image).  If none is configured, verification records L3=0 with an explicit
reason and the hard floor rejects the candidate.
"""

from __future__ import annotations

import time
import uuid
from pathlib import Path
from typing import Any

import yaml

from ..config import Config, credentials
from ..controls import Control
from ..verify.bisimulation import Snapshot, normalize
from ..verify.sandbox import ExecResult, OraFileSandbox, Sandbox
from ..verify.sqltools import Statement
from .oracle import OracleClient, quote_container


def load_snapshot_views(path: Path | None) -> dict[str, str]:
    if not path or not path.exists():
        raise FileNotFoundError(f"snapshot view file not found: {path}")
    d = yaml.safe_load(path.read_text())
    views = dict(d.get("views", {}))
    for name in d.get("enable_optional", []) or []:
        views[name] = d["optional_views"][name]
    return views


class _OracleSandboxBase(Sandbox):
    def __init__(self, client: OracleClient, views: dict[str, str]):
        self.client = client
        self.views = views
        self.snapshot_errors: list[str] = []

    def evaluate_invariant(self, control: Control) -> frozenset | None:
        sql = control.invariant()
        if not sql:
            return None
        return frozenset(self.client.query(sql))

    def can_evaluate(self, control: Control) -> bool:
        return control.invariant() is not None

    def snapshot(self) -> Snapshot:
        snap: Snapshot = {}
        for name, sql in self.views.items():
            try:
                cols, rows = self.client.query_with_columns(sql)
                snap[name] = normalize(rows, cols)
            except Exception as e:  # noqa: BLE001
                # A view that cannot be read must not silently pass Layer 3: record a sentinel
                # that differs on every call so the comparison fails loudly.
                self.snapshot_errors.append(f"{name}: {str(e).splitlines()[0]}")
                snap[name] = frozenset({("__SNAPSHOT_ERROR__", time.time_ns())})
        return snap

    def execute(self, statements: list[Statement]) -> ExecResult:
        return self.client.execute_statements(statements)


class ShadowPdbSandbox(_OracleSandboxBase):
    name = "shadow-pdb"

    def __init__(self, cfg: Config, source_pdb: str, exadata: bool):
        sb = cfg.get("sandbox")
        dsn, user, pwd = credentials(sb, "admin_dsn_env", "admin_user_env", "admin_password_env")
        client = OracleClient(dsn, user, pwd, sysdba=bool(sb.get("admin_sysdba")))
        super().__init__(client, load_snapshot_views(cfg.path("sandbox.snapshot_views_file")))
        self.source = quote_container(source_pdb)
        self.shadow = f"ORAREM_SHADOW_{uuid.uuid4().hex[:8].upper()}"
        clause = sb["clone_clause_exadata"] if exadata else sb["clone_clause_default"]
        fmt: dict[str, Any] = {"shadow": self.shadow, "source": self.source, "clause": clause}
        self._drop = [sb["close_sql"].format(**fmt), sb["drop_sql"].format(**fmt)]
        client.set_container("CDB$ROOT")
        t0 = time.time()
        for sql in (sb["clone_sql"].format(**fmt).strip(), sb["open_sql"].format(**fmt)):
            with client.conn.cursor() as cur:
                cur.execute(sql)
        self.clone_seconds = time.time() - t0
        client.set_container(self.shadow)

    def close(self) -> None:
        try:
            self.client.set_container("CDB$ROOT")
            for sql in self._drop:
                with self.client.conn.cursor() as cur:
                    cur.execute(sql)
        finally:
            self.client.close()


class CdbSandbox(_OracleSandboxBase):
    """A disposable CDB for CDB-scope parameters (reset it out-of-band after use)."""

    name = "cdb-sandbox"

    def __init__(self, cfg: Config):
        sb = cfg.get("sandbox.cdb_sandbox")
        dsn, user, pwd = credentials(sb)
        client = OracleClient(dsn, user, pwd, sysdba=bool(sb.get("sysdba")))
        super().__init__(client, load_snapshot_views(cfg.path("sandbox.snapshot_views_file")))
        client.set_container("CDB$ROOT")

    def close(self) -> None:
        self.client.close()


class UnavailableSandbox(Sandbox):
    """Placeholder that makes verification fail explicitly (never silently pass)."""

    name = "unavailable"

    def __init__(self, reason: str):
        self.reason = reason

    def can_evaluate(self, control: Control) -> bool:
        return False

    def evaluate_invariant(self, control: Control) -> frozenset | None:
        return None

    def snapshot(self) -> Snapshot:
        return {"__UNAVAILABLE__": frozenset({(self.reason, time.time_ns())})}

    def execute(self, statements: list[Statement]) -> ExecResult:
        return ExecResult(ok=False, errors=[self.reason])


class OracleSandboxProvider:
    """Chooses the sandbox for a finding: file, shadow PDB, or CDB sandbox."""

    def __init__(self, cfg: Config):
        self.cfg = cfg

    def open(self, control: Control, container: str, context: dict[str, Any]) -> Sandbox:
        if control.is_file_control:
            files = {"sqlnet.ora": self.cfg.get("files.sqlnet_ora"), "listener.ora": self.cfg.get("files.listener_ora")}
            return OraFileSandbox(files, self.cfg.get("files.listeners"))
        scope = resolve_scope(control, context)
        try:
            if scope == "cdb" or container in ("CDB$ROOT", "HOST"):
                if not self.cfg.get("sandbox.cdb_sandbox.dsn_env") or not _env_present(self.cfg.get("sandbox.cdb_sandbox")):
                    return UnavailableSandbox("CDB-scope control: no disposable CDB sandbox configured "
                                              "(sandbox.cdb_sandbox); a PDB clone cannot verify it")
                return CdbSandbox(self.cfg)
            ex = self.cfg.get("sandbox.exadata")
            exadata = bool(context.get("topology", {}).get("is_exadata")) if ex == "auto" else bool(ex)
            return ShadowPdbSandbox(self.cfg, container, exadata)
        except Exception as e:  # noqa: BLE001
            return UnavailableSandbox(f"sandbox creation failed: {str(e).splitlines()[0]}")


def _env_present(section: dict) -> bool:
    import os
    return all(os.environ.get(section.get(k) or "") for k in ("dsn_env", "user_env", "password_env"))


def resolve_scope(control: Control, context: dict[str, Any]) -> str:
    if control.scope in ("pdb", "cdb", "file"):
        return control.scope
    if control.kind == "parameter":
        pc = context.get("dependency", {}).get("parameter", {})
        return "pdb" if str(pc.get("ispdb_modifiable", "FALSE")).upper() == "TRUE" else "cdb"
    if control.kind == "public_execute":
        rows = (context.get("dependency", {}).get("public_grant") or {}).get("rows") or []
        if any(str(r[2]).upper() == "YES" for r in rows):
            return "cdb"  # common grant: revocable only from CDB$ROOT with CONTAINER=ALL
    return "pdb"
