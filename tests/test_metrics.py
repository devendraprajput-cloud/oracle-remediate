from math import comb

import pytest

from oracle_remediate.eval.metrics import calibrate_thresholds, cohen_kappa, mean_ci95, pass_at_k


@pytest.mark.parametrize("n,c,k", [(10, 3, 1), (10, 3, 5), (10, 0, 3), (10, 10, 1), (10, 7, 5), (5, 1, 5)])
def test_pass_at_k_matches_binomial_definition(n, c, k):
    expected = 1.0 - (comb(n - c, k) / comb(n, k) if n - c >= k else 0.0)
    assert pass_at_k(n, c, k) == pytest.approx(expected)


def test_known_values():
    assert pass_at_k(10, 3, 1) == pytest.approx(0.3)
    assert pass_at_k(10, 3, 5) == pytest.approx(1 - 21 / 252)


def test_kappa():
    assert cohen_kappa([1, 1, 0, 0], [1, 1, 0, 0]) == pytest.approx(1.0)
    assert cohen_kappa([1, 0, 1, 0], [1, 1, 0, 0]) == pytest.approx(0.0)


def test_ci_t_interval():
    r = mean_ci95([0.8, 0.82, 0.78, 0.81, 0.79])
    assert r["mean"] == pytest.approx(0.8) and r["lo"] < 0.8 < r["hi"] and r["n"] == 5


def test_calibration_zero_false_auto_apply():
    pts = [(0.95, True), (0.9, True), (0.86, False), (0.7, True), (0.6, False), (0.3, False)]
    r = calibrate_thresholds(pts)
    assert r["tau_auto"] > 0.86
    assert all(c < r["tau_auto"] for c, ok in pts if not ok)
