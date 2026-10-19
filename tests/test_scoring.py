import pytest

from oracle_remediate.models import Disposition
from oracle_remediate.scoring.confidence import ScoringSettings, Weights, confidence, risk_score
from oracle_remediate.scoring.policy import DecisionSettings, PolicyContext, Thresholds, decide


def L(l1=1, l2=1, l3=1, rb=1):
    return {"L1": l1, "L2": l2, "L3": l3, "L_RB": rb}


def test_formula_matches_paper():
    c = confidence(0.8, 1, 1, 0, 1, "medium")
    # 0.4*0.8 + 0.3*(2/3) + 0.2*1 + 0.1*0.6
    assert c.C == pytest.approx(0.32 + 0.2 + 0.2 + 0.06)
    assert c.V == pytest.approx(2 / 3)


def test_risk_mapping_and_unknown_is_conservative():
    assert risk_score("low") == 1.0 and risk_score("MEDIUM") == 0.6 and risk_score("high") == 0.3
    assert risk_score(None) == 0.3 and risk_score("banana") == 0.3


def test_weights_must_sum_to_one():
    with pytest.raises(ValueError):
        confidence(1, 1, 1, 1, 1, "low", ScoringSettings(Weights(0.5, 0.5, 0.5, 0.0)))


def test_thresholds():
    s = DecisionSettings()
    assert decide(confidence(1, 1, 1, 1, 1, "low"), L(), s).disposition is Disposition.AUTO_APPLY
    assert decide(confidence(0.4, 1, 1, 1, 1, "medium"), L(), s).disposition is Disposition.MANUAL_REVIEW
    assert decide(confidence(0.2, 0, 1, 1, 1, "high"), L(0), s).disposition is Disposition.REJECT


@pytest.mark.parametrize("layers", [L(l3=0), L(rb=0)])
def test_hard_floor_forces_reject(layers):
    c = confidence(1.0, layers["L1"], layers["L2"], layers["L3"], layers["L_RB"], "low")
    d = decide(c, layers, DecisionSettings())
    assert d.disposition is Disposition.REJECT and d.hard_floor


def test_paper_mode_auto_applies_unfixed_candidate_but_strict_mode_does_not():
    # A=1, L2=0 (finding NOT fixed), L3=1, L_RB=1, low risk -> C = 0.4 + 0.2 + 0.2 + 0.1 = 0.90 >= 0.85
    layers = L(l2=0)
    c = confidence(1.0, 1, 0, 1, 1, "low")
    assert c.C == pytest.approx(0.90)
    paper = decide(c, layers, DecisionSettings(strict_auto_apply=False))
    strict = decide(c, layers, DecisionSettings(strict_auto_apply=True))
    assert paper.disposition is Disposition.AUTO_APPLY
    assert strict.disposition is Disposition.MANUAL_REVIEW


def test_review_only_override_caps_at_manual_review():
    d = decide(confidence(1, 1, 1, 1, 1, "low"), L(), DecisionSettings(), review_only=True, review_reasons=["audit"])
    assert d.disposition is Disposition.MANUAL_REVIEW and d.overrides


def test_threshold_validation():
    with pytest.raises(ValueError):
        decide(confidence(1, 1, 1, 1, 1, "low"), L(), DecisionSettings(Thresholds(0.5, 0.9)))


def test_policy_exceptions_and_windows(tmp_path):
    import datetime as dt
    p = tmp_path / "p.yaml"
    p.write_text("exceptions:\n  - {control_id: a, container: '*', reason: r, expires: 2000-01-01}\n"
                 "  - {control_id: b, container: PDB1, reason: r}\n"
                 "change_windows:\n  - {days: [Sat], start: '22:00', end: '02:00'}\n")
    pol = PolicyContext.load(p)
    assert pol.exception_for("a", "X") is None  # expired
    assert pol.exception_for("b", "PDB1") and pol.exception_for("b", "PDB2") is None
    assert pol.in_change_window(dt.datetime(2026, 10, 17, 23, 0))  # Saturday 23:00
    assert pol.in_change_window(dt.datetime(2026, 10, 18, 1, 0))  # Sunday 01:00 (window started Sat)
    assert not pol.in_change_window(dt.datetime(2026, 10, 18, 23, 0))
