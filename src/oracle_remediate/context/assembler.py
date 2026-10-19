"""Context Assembly Layer (paper Section III.B) -- a primary research contribution.

For each finding the layer retrieves four context classes; each one can be
switched off for the RQ3 ablation (``context.topology``, ``context.dependency``,
``context.documentation``, ``context.policy``).
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any

from ..controls import Control
from ..models import Finding
from ..rag.retriever import DocumentRetriever
from ..scoring.policy import PolicyContext
from .sources import ContextSource


@dataclass
class ContextFlags:
    topology: bool = True
    dependency: bool = True
    documentation: bool = True
    policy: bool = True

    @classmethod
    def from_config(cls, cfg) -> ContextFlags:
        return cls(*(bool(cfg.get(f"context.{k}", True)) for k in ("topology", "dependency", "documentation", "policy")))


class ContextAssembler:
    def __init__(self, source: ContextSource | None, retriever: DocumentRetriever | None,
                 policy: PolicyContext, flags: ContextFlags):
        self.source = source
        self.retriever = retriever
        self.policy = policy
        self.flags = flags
        self._topology_cache: dict[str, Any] | None = None

    def assemble(self, finding: Finding, control: Control) -> dict[str, Any]:
        ctx: dict[str, Any] = {"flags": self.flags.__dict__.copy(), "timings": {}}
        if self.flags.topology and self.source:
            t0 = time.time()
            if self._topology_cache is None:
                self._topology_cache = _safe(self.source.topology)
            ctx["topology"] = self._topology_cache
            ctx["timings"]["topology_s"] = round(time.time() - t0, 4)
        if self.flags.dependency and self.source:
            t0 = time.time()
            ctx["dependency"] = _safe(lambda: self.source.dependencies(control, finding))
            ctx["timings"]["dependency_s"] = round(time.time() - t0, 4)
        if self.flags.documentation and self.retriever:
            t0 = time.time()
            ctx["documentation"] = _safe(lambda: self.retriever.retrieve(control, finding))
            ctx["timings"]["documentation_s"] = round(time.time() - t0, 4)
        if self.flags.policy:
            pol = self.policy.summary()
            pol["exceptions"] = [e for e in pol["exceptions"] if e.get("control_id") == control.id]
            pol["in_change_window_now"] = self.policy.in_change_window()
            ctx["policy"] = pol
        return ctx


def _safe(fn) -> Any:
    try:
        return fn()
    except Exception as e:  # noqa: BLE001 - context failures must not abort remediation
        return {"error": f"{type(e).__name__}: {str(e).splitlines()[0] if str(e) else ''}"}
