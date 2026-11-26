"""Cost-sensitive policy, feature-group importance and operational slices."""

from __future__ import annotations

import numpy as np
import pandas as pd
from sklearn.metrics import confusion_matrix

from .config import FALSE_NEGATIVE_COST, FALSE_POSITIVE_COST, FEATURE_GROUPS, TARGET


def policy_curve(
    labels: np.ndarray,
    scores: np.ndarray,
    fn_cost: float = FALSE_NEGATIVE_COST,
    fp_cost: float = FALSE_POSITIVE_COST,
) -> pd.DataFrame:
    rows = []
    for threshold in np.round(np.arange(0.01, 1.0, 0.01), 2):
        predictions = (scores >= threshold).astype(int)
        matrix = confusion_matrix(labels, predictions, labels=[0, 1])
        _, fp, fn, tp = matrix.ravel()
        total_cost = fn_cost * fn + fp_cost * fp
        rows.append(
            {
                "threshold": float(threshold),
                "precision": float(tp / (tp + fp)) if tp + fp else 0.0,
                "recall": float(tp / (tp + fn)) if tp + fn else 0.0,
                "f1": float(2 * tp / (2 * tp + fp + fn)) if 2 * tp + fp + fn else 0.0,
                "flagged_rate": float(predictions.mean()),
                "missed_phishing": int(fn),
                "false_alarms": int(fp),
                "total_cost": float(total_cost),
                "cost_per_1000": round(float(total_cost / len(labels) * 1000), 2),
            }
        )
    return pd.DataFrame(rows)


def choose_policy(curve: pd.DataFrame) -> dict:
    best = curve.loc[curve["cost_per_1000"].idxmin()]
    return {
        "threshold": float(best["threshold"]),
        "cost_per_1000": float(best["cost_per_1000"]),
        "recall": float(best["recall"]),
        "precision": float(best["precision"]),
        "flagged_rate": float(best["flagged_rate"]),
        "missed_phishing": int(best["missed_phishing"]),
        "false_alarms": int(best["false_alarms"]),
        "fn_cost": FALSE_NEGATIVE_COST,
        "fp_cost": FALSE_POSITIVE_COST,
    }


def feature_group_importance(importance: pd.DataFrame) -> pd.DataFrame:
    rows = []
    for group, columns in FEATURE_GROUPS.items():
        subset = importance[importance["feature"].isin(columns)]
        rows.append(
            {
                "group": group,
                "features": len(columns),
                "importance_mean": round(float(subset["importance_mean"].sum()), 5),
                "importance_std": round(float(subset["importance_std"].sum()), 5),
                "top_feature": subset.sort_values("importance_mean", ascending=False).iloc[0]["feature"] if not subset.empty else "",
            }
        )
    return pd.DataFrame(rows).sort_values("importance_mean", ascending=False).reset_index(drop=True)


def operational_slices(scored: pd.DataFrame, column: str) -> pd.DataFrame:
    rows = []
    for group, subset in scored.groupby(column, dropna=False):
        labels = subset[TARGET].to_numpy()
        predictions = subset["prediction"].to_numpy()
        tp = int(((predictions == 1) & (labels == 1)).sum())
        fp = int(((predictions == 1) & (labels == 0)).sum())
        fn = int(((predictions == 0) & (labels == 1)).sum())
        rows.append(
            {
                "slice": column,
                "group": str(group),
                "sites": len(subset),
                "phishing": int(labels.sum()),
                "flag_rate": round(float(predictions.mean()), 4),
                "recall": round(tp / (tp + fn), 4) if tp + fn else np.nan,
                "precision": round(tp / (tp + fp), 4) if tp + fp else np.nan,
                "mean_score": round(float(subset["probability"].mean()), 4),
            }
        )
    return pd.DataFrame(rows)


def action_for_tier(tier: str) -> str:
    return {
        "Low": "Allow with normal monitoring",
        "Moderate": "Review site metadata",
        "High": "Block or quarantine",
        "Critical": "Block immediately and investigate",
    }.get(tier, "Review site metadata")
