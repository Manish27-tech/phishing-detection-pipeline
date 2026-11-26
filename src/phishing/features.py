"""Risk aggregation and preprocessing for phishing detection."""

from __future__ import annotations

import numpy as np
import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.impute import SimpleImputer
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

from .config import (
    FEATURE_GROUPS,
    FEATURES,
    NUMERIC_FEATURES,
    RAW_FEATURES,
)


def build_features(frame: pd.DataFrame) -> pd.DataFrame:
    """Aggregate suspicious indicators by feature family."""
    out = frame.copy()
    for column in RAW_FEATURES:
        out[column] = pd.to_numeric(out[column], errors="coerce").fillna(0).clip(-1, 1)

    out["risk_count"] = (out[RAW_FEATURES] == -1).sum(axis=1)
    out["suspicious_count"] = (out[RAW_FEATURES] == 0).sum(axis=1)
    out["safe_count"] = (out[RAW_FEATURES] == 1).sum(axis=1)
    out["risk_ratio"] = (out["risk_count"] + 0.5 * out["suspicious_count"]) / len(RAW_FEATURES)

    for group, columns in FEATURE_GROUPS.items():
        out[f"{group}_risk_count"] = (out[columns] == -1).sum(axis=1)

    out[NUMERIC_FEATURES] = out[NUMERIC_FEATURES].replace([np.inf, -np.inf], np.nan)
    return out


def build_preprocessor() -> ColumnTransformer:
    numeric = Pipeline(
        [
            ("imputer", SimpleImputer(strategy="median")),
            ("scaler", StandardScaler()),
        ]
    )
    return ColumnTransformer(
        [("numeric", numeric, NUMERIC_FEATURES)],
        remainder="drop",
        verbose_feature_names_out=False,
    )


def model_input(frame: pd.DataFrame) -> pd.DataFrame:
    return build_features(frame)[FEATURES]


def feature_names(preprocessor: ColumnTransformer) -> list[str]:
    return list(preprocessor.get_feature_names_out())
