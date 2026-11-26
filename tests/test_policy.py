import numpy as np

from phishing.evaluate import score_frame
from phishing.policy import (
    action_for_tier,
    choose_policy,
    feature_group_importance,
    operational_slices,
    policy_curve,
)


def test_policy_curve_is_complete():
    rng = np.random.default_rng(3)
    labels = rng.integers(0, 2, 800)
    scores = np.clip(labels * 0.35 + rng.random(800) * 0.5, 0, 1)
    curve = policy_curve(labels, scores)
    assert len(curve) == 99
    assert curve["cost_per_1000"].min() <= curve["cost_per_1000"].max()
    assert (curve["missed_phishing"] >= 0).all()


def test_choose_policy_returns_best_row():
    rng = np.random.default_rng(4)
    labels = rng.integers(0, 2, 500)
    scores = rng.random(500)
    curve = policy_curve(labels, scores)
    chosen = choose_policy(curve)
    assert chosen["cost_per_1000"] == curve["cost_per_1000"].min()
    assert 0 < chosen["threshold"] < 1


def test_feature_group_importance(sample):
    import pandas as pd

    importance = pd.DataFrame(
        {
            "feature": ["URL_Length", "SSLfinal_State", "URL_of_Anchor", "web_traffic"],
            "importance_mean": [0.01, 0.02, 0.03, 0.04],
            "importance_std": [0.001, 0.002, 0.003, 0.004],
        }
    )
    table = feature_group_importance(importance)
    assert len(table) == 4
    assert table["importance_mean"].sum() > 0


def test_operational_slices(sample):
    scores = np.linspace(0, 1, len(sample))
    scored = score_frame(sample, scores, 0.3)
    table = operational_slices(scored, "risk_band")
    assert table["sites"].sum() == len(sample)
    assert {"flag_rate", "recall", "precision", "mean_score"}.issubset(table.columns)


def test_action_mapping():
    assert action_for_tier("Critical").startswith("Block")
    assert action_for_tier("Low").startswith("Allow")
    assert action_for_tier("unknown").startswith("Review")
