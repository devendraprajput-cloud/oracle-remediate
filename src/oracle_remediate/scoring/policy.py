"""Decision policy (paper Section III.D-2) and policy-context file handling.

    disposition(C) = AUTO-APPLY     if C >= tau_auto
                     MANUAL-REVIEW  if tau_review <= C < tau_auto
                     REJECT         if C < tau_review

Hard floors (paper): L3 == 0 or L_RB == 0  ->  REJECT regardless of C.
Per-control overrides (paper): review-only controls cap any disposition above
REJECT at MANUAL-REVIEW.

Implementation safeguard (``strict_auto_apply``, default True, documented as
deviation D1 in docs/DESIGN_NOTES.md): AUTO-APPLY additionally requires
L1 == L2 == 1.  With the paper's weights, a candidate with A=1, R=low, L3=1,
L_RB=1 but L2=0 (did NOT fix the finding) scores C=0.90 >= 0.85 and would be
auto-applied.  Set ``strict_auto_apply: false`` to reproduce the paper exactly.
"""

from __future__ import annotations

import datetime as dt
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from ..models import ConfidenceBreakdown, Decision, Disposition


@dataclass
class Thresholds:
    tau_auto: float = 0.85
    tau_review: float = 0.55

    def validate(self) -> None:
        if not (0.0 <= self.tau_review <= self.tau_auto <= 1.0):
            raise ValueError("require 0 <= tau_review <= tau_auto <= 1")


@dataclass
class ChangeWindow:
    days: list[str]  # Mon..Sun
    start: str  # HH:MM
    end: str  # HH:MM (may wrap past midnight)

    def contains(self, when: dt.datetime) -> bool:
        day = when.strftime("%a")
        t = when.strftime("%H:%M")
        if self.start <= self.end:
            return day in self.days and self.start <= t < self.end
        # window wraps midnight: belongs to the day it started
        prev = (when - dt.timedelta(days=1)).strftime("%a")
        return (day in self.days and t >= self.start) or (prev in self.days and t < self.end)


@dataclass
class PolicyContext:
    """Organisation-level overrides (paper III.B 'Policy context')."""

    exceptions: list[dict[str, Any]] = field(default_factory=list)
    change_windows: list[ChangeWindow] = field(default_factory=list)
    service_accounts: list[str] = field(default_factory=list)
    review_only_controls: list[str] = field(default_factory=list)
    timezone: str = "UTC"

    @classmethod
    def load(cls, path: str | Path | None) -> PolicyContext:
        if not path or not Path(path).exists():
            return cls()
        d = yaml.safe_load(Path(path).read_text()) or {}
        return cls(
            exceptions=d.get("exceptions", []),
            change_windows=[ChangeWindow(**w) for w in d.get("change_windows", [])],
            service_accounts=[s.upper() for s in d.get("service_accounts", [])],
            review_only_controls=d.get("review_only_controls", []),
            timezone=d.get("timezone", "UTC"),
        )

    def exception_for(self, control_id: str, container: str, today: dt.date | None = None) -> dict | None:
        today = today or dt.date.today()
        for e in self.exceptions:
            if e.get("control_id") != control_id:
                continue
            if e.get("container") not in (None, "*", container):
                continue
            exp = e.get("expires")
            if exp and dt.date.fromisoformat(str(exp)) < today:
                continue
            return e
        return None

    def in_change_window(self, when: dt.datetime | None = None) -> bool:
        if not self.change_windows:
            return False
        if when is None:
            try:
                from zoneinfo import ZoneInfo
                when = dt.datetime.now(ZoneInfo(self.timezone))
            except Exception:  # pragma: no cover
                when = dt.datetime.utcnow()
        return any(w.contains(when) for w in self.change_windows)

    def summary(self) -> dict[str, Any]:
        return {
            "exceptions": [{k: e.get(k) for k in ("control_id", "container", "reason", "expires")} for e in self.exceptions],
            "change_windows": [w.__dict__ for w in self.change_windows],
            "service_accounts": self.service_accounts,
            "review_only_controls": self.review_only_controls,
        }


@dataclass
class DecisionSettings:
    thresholds: Thresholds = field(default_factory=Thresholds)
    hard_floor_layers: list[str] = field(default_factory=lambda: ["L3", "L_RB"])
    strict_auto_apply: bool = True


def decide(conf: ConfidenceBreakdown, layers: dict[str, int], settings: DecisionSettings,
           review_only: bool = False, review_reasons: list[str] | None = None) -> Decision:
    settings.thresholds.validate()
    t = settings.thresholds
    reasons: list[str] = []
    overrides: list[str] = []

    if conf.C >= t.tau_auto:
        disp = Disposition.AUTO_APPLY
    elif conf.C >= t.tau_review:
        disp = Disposition.MANUAL_REVIEW
    else:
        disp = Disposition.REJECT
    reasons.append(f"C={conf.C:.3f} vs tau_auto={t.tau_auto}, tau_review={t.tau_review} -> {disp.value}")

    floors = [name for name in settings.hard_floor_layers if layers.get(name, 0) == 0]
    if floors:
        disp = Disposition.REJECT
        reasons.append(f"hard floor: {', '.join(floors)} == 0 -> REJECT regardless of C")

    if disp is Disposition.AUTO_APPLY and settings.strict_auto_apply:
        missing = [n for n in ("L1", "L2") if layers.get(n, 0) == 0]
        if missing:
            disp = Disposition.MANUAL_REVIEW
            overrides.append(f"strict_auto_apply: {', '.join(missing)} == 0 caps at MANUAL-REVIEW")

    if review_only and disp is not Disposition.REJECT and disp is not Disposition.MANUAL_REVIEW:
        disp = Disposition.MANUAL_REVIEW
        overrides.append("review-only override: " + ("; ".join(review_reasons or []) or "per-control policy"))
    elif review_only and disp is Disposition.MANUAL_REVIEW and review_reasons:
        overrides.append("review-only: " + "; ".join(review_reasons))

    return Decision(disposition=disp, confidence=conf, hard_floor=floors, overrides=overrides, reasons=reasons)
