"""Core data model shared by every layer (paper Section III).

The objects mirror the messages in the end-to-end sequence diagram (Fig. 1):
``Finding`` (audit -> ingestion), ``Candidate`` / ``GenerationResult``
(LLM generator), ``LayerResult`` / ``VerifierReport`` / ``RollbackReport``
(safety and rollback verifiers) and ``Decision`` (confidence scorer).
"""

from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any


class Disposition(str, Enum):
    """Operational dispositions of Section III.D-2."""

    AUTO_APPLY = "AUTO-APPLY"
    MANUAL_REVIEW = "MANUAL-REVIEW"
    REJECT = "REJECT"


# --------------------------------------------------------------------------- findings
@dataclass
class Finding:
    """Normalised finding schema of Section III.A (deliberately minimal)."""

    control_id: str
    title: str = ""
    observed_value: str = ""
    expected_value: str = ""
    affected_containers: list[str] = field(default_factory=list)
    affected_grantees: list[str] = field(default_factory=list)
    raw_audit_sql: str = ""
    cis_id: str | None = None
    source: str = "orarem-audit"

    @property
    def container(self) -> str:
        """Primary container the finding applies to ("CDB$ROOT" if unspecified)."""
        return self.affected_containers[0] if self.affected_containers else "CDB$ROOT"

    @property
    def finding_id(self) -> str:
        key = f"{self.control_id}|{','.join(sorted(self.affected_containers))}|{self.observed_value}"
        return f"{self.control_id}__{self.container}__{hashlib.sha1(key.encode()).hexdigest()[:8]}"

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["finding_id"] = self.finding_id
        return d


# --------------------------------------------------------------------------- generation
@dataclass
class TokenUsage:
    input_tokens: int = 0
    output_tokens: int = 0

    def __add__(self, other: TokenUsage) -> TokenUsage:
        return TokenUsage(self.input_tokens + other.input_tokens, self.output_tokens + other.output_tokens)


@dataclass
class Candidate:
    """One parsed LLM sample following the strict output schema of Section III.C."""

    sample_index: int
    remediation_sql: str = ""
    rollback_sql: str = ""
    verification_sql: str = ""
    prerequisites: list[str] = field(default_factory=list)
    risk_level: str = ""
    assumptions: list[str] = field(default_factory=list)
    rationale: str = ""
    raw_text: str = ""
    parse_error: str | None = None
    canonical: str = ""
    usage: TokenUsage = field(default_factory=TokenUsage)
    latency_s: float = 0.0
    temperature_applied: float | None = None

    @property
    def valid(self) -> bool:
        return self.parse_error is None and bool(self.remediation_sql.strip())


@dataclass
class GenerationResult:
    candidates: list[Candidate]
    plurality: Candidate | None
    agreement: float
    plurality_count: int
    backend: str
    model: str
    temperature_requested: float | None
    temperature_applied: float | None
    usage: TokenUsage = field(default_factory=TokenUsage)
    wall_clock_s: float = 0.0
    prompt_chars: int = 0


# --------------------------------------------------------------------------- verification
@dataclass
class LayerResult:
    passed: int  # 0 or 1, recorded outcome L_i (informational, never gating)
    detail: str = ""
    evidence: dict[str, Any] = field(default_factory=dict)


@dataclass
class VerifierReport:
    L1: LayerResult
    L2: LayerResult
    L3: LayerResult
    executed: bool = False
    notes: list[str] = field(default_factory=list)

    @property
    def V(self) -> float:  # noqa: N802 - paper notation
        return (self.L1.passed + self.L2.passed + self.L3.passed) / 3.0


@dataclass
class RollbackReport:
    L_RB: LayerResult


# --------------------------------------------------------------------------- decision
@dataclass
class ConfidenceBreakdown:
    A: float
    V: float
    L_RB: int
    R: float
    weights: dict[str, float]
    C: float


@dataclass
class Decision:
    disposition: Disposition
    confidence: ConfidenceBreakdown | None
    hard_floor: list[str] = field(default_factory=list)
    overrides: list[str] = field(default_factory=list)
    reasons: list[str] = field(default_factory=list)


@dataclass
class FindingOutcome:
    finding: Finding
    status: str  # processed | out_of_scope | excepted | unknown_control | generation_failed
    decision: Decision
    control_class: str | None = None
    context_summary: dict[str, Any] = field(default_factory=dict)
    generation: GenerationResult | None = None
    verifier: VerifierReport | None = None
    rollback: RollbackReport | None = None
    candidate_evaluations: list[dict[str, Any]] = field(default_factory=list)
    apply_result: dict[str, Any] | None = None
    timings: dict[str, float] = field(default_factory=dict)
    artifact_dir: str | None = None


def to_jsonable(obj: Any) -> Any:
    """Recursively convert dataclasses / enums to JSON-serialisable structures."""
    if isinstance(obj, Enum):
        return obj.value
    if hasattr(obj, "__dataclass_fields__"):
        out = {k: to_jsonable(getattr(obj, k)) for k in obj.__dataclass_fields__}
        if isinstance(obj, Finding):
            out["finding_id"] = obj.finding_id
        if isinstance(obj, VerifierReport):
            out["V"] = obj.V
        return out
    if isinstance(obj, dict):
        return {str(k): to_jsonable(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple, set, frozenset)):
        return [to_jsonable(v) for v in obj]
    return obj
