"""Confidence score C (paper Section III.D-1).

    C = w_A*A + w_V*V + w_RB*L_RB + w_R*R,    w_A + w_V + w_RB + w_R = 1

Initial weights (paper): w_A=0.40, w_V=0.30, w_RB=0.20, w_R=0.10.
Risk mapping (paper): low -> 1.0, medium -> 0.6, high -> 0.3.  A missing or
unrecognised risk_level maps to the most conservative value (0.3).
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ..models import ConfidenceBreakdown

RISK_MAP = {"low": 1.0, "medium": 0.6, "high": 0.3}


@dataclass
class Weights:
    A: float = 0.40
    V: float = 0.30
    RB: float = 0.20
    R: float = 0.10

    def validate(self) -> None:
        total = self.A + self.V + self.RB + self.R
        if abs(total - 1.0) > 1e-9:
            raise ValueError(f"confidence weights must sum to 1.0 (got {total})")
        if min(self.A, self.V, self.RB, self.R) < 0:
            raise ValueError("confidence weights must be non-negative")

    def as_dict(self) -> dict[str, float]:
        return {"w_A": self.A, "w_V": self.V, "w_RB": self.RB, "w_R": self.R}


@dataclass
class ScoringSettings:
    weights: Weights = field(default_factory=Weights)
    risk_map: dict[str, float] = field(default_factory=lambda: dict(RISK_MAP))


def risk_score(risk_level: str | None, risk_map: dict[str, float] | None = None) -> float:
    m = risk_map or RISK_MAP
    return m.get((risk_level or "").strip().lower(), min(m.values()))


def confidence(A: float, L1: int, L2: int, L3: int, L_RB: int, risk_level: str | None,
               settings: ScoringSettings | None = None) -> ConfidenceBreakdown:
    s = settings or ScoringSettings()
    s.weights.validate()
    V = (L1 + L2 + L3) / 3.0
    R = risk_score(risk_level, s.risk_map)
    w = s.weights
    C = w.A * A + w.V * V + w.RB * L_RB + w.R * R
    return ConfidenceBreakdown(A=round(A, 6), V=round(V, 6), L_RB=int(L_RB), R=R, weights=w.as_dict(),
                               C=round(min(1.0, max(0.0, C)), 6))
