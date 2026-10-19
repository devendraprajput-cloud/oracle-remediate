"""Sandbox abstraction for Layer 2/3 and the rollback round trip.

Concrete sandboxes:
  * :class:`oracle_remediate.db.shadow_pdb.ShadowPdbSandbox` -- shadow PDB cloned with
    ``CREATE PLUGGABLE DATABASE ... SNAPSHOT COPY`` (Exadata) or a full/hot clone
  * :class:`oracle_remediate.db.shadow_pdb.CdbSandbox` -- a disposable CDB (e.g. the
    benchmark Docker image) for CDB-scope parameters that a PDB cannot change
  * :class:`OraFileSandbox` -- temporary copies of listener.ora / sqlnet.ora
  * :class:`oracle_remediate.sim.simulator.SimulatedSandbox` -- offline simulator
"""

from __future__ import annotations

import shutil
import tempfile
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path

from ..controls import Control
from . import orafile
from .bisimulation import Snapshot
from .sqltools import Statement


@dataclass
class ExecResult:
    ok: bool = True
    errors: list[str] = field(default_factory=list)
    executed: int = 0


class Sandbox(ABC):
    """A disposable copy of the target on which candidates may be executed."""

    name: str = "sandbox"

    @abstractmethod
    def evaluate_invariant(self, control: Control) -> frozenset | None:
        """Rows returned by phi_c (empty == compliant); None if not evaluable here."""

    @abstractmethod
    def snapshot(self) -> Snapshot: ...

    @abstractmethod
    def execute(self, statements: list[Statement]) -> ExecResult: ...

    def can_evaluate(self, control: Control) -> bool:
        return True

    def close(self) -> None:  # pragma: no cover - overridden where needed
        pass

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


class OraFileSandbox(Sandbox):
    """Applies ORA_SET / ORA_UNSET to temporary copies of the Oracle Net files."""

    name = "ora-file"

    def __init__(self, files: dict[str, str | Path], listeners: list[str]):
        self._dir = Path(tempfile.mkdtemp(prefix="orarem_ora_"))
        self.listeners = listeners
        self.files: dict[str, Path] = {}
        for logical, src in files.items():
            dst = self._dir / logical
            if src and Path(src).exists():
                shutil.copy(src, dst)
            else:
                dst.write_text("")
            self.files[logical.lower()] = dst

    def can_evaluate(self, control: Control) -> bool:
        return control.kind == "ora_file" and control.params.get("file", "").lower() in self.files

    def evaluate_invariant(self, control: Control) -> frozenset | None:
        if not self.can_evaluate(control):
            return None
        text = self.files[control.params["file"].lower()].read_text()
        return frozenset(orafile.evaluate(text, control.params, self.listeners))

    def snapshot(self) -> Snapshot:
        return {f"FILE:{k}": frozenset(orafile.as_dict(p.read_text()).items()) for k, p in self.files.items()}

    def execute(self, statements: list[Statement]) -> ExecResult:
        res = ExecResult()
        for st in statements:
            a = st.attrs
            f = (a.get("file") or "").lower()
            if st.kind not in ("ORA_SET", "ORA_UNSET") or f not in self.files or a.get("malformed"):
                res.ok = False
                res.errors.append(f"cannot apply {st.kind} to {f!r} in file sandbox")
                continue
            p = self.files[f]
            txt = p.read_text()
            txt = orafile.set_key(txt, a["key"], a["value"]) if st.kind == "ORA_SET" else orafile.unset_key(txt, a["key"])
            p.write_text(txt)
            res.executed += 1
        return res

    def read(self, logical: str) -> str:
        return self.files[logical.lower()].read_text()

    def close(self) -> None:
        shutil.rmtree(self._dir, ignore_errors=True)
