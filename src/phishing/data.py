"""Load, clean and split the UCI phishing-websites dataset."""

from __future__ import annotations

from pathlib import Path

import pandas as pd
from sklearn.model_selection import train_test_split

from .config import DATA_RAW, RANDOM_STATE, RAW_FEATURES, TARGET, TEST_SIZE, VAL_SIZE


def load_raw(path: str | Path = DATA_RAW) -> pd.DataFrame:
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(
            f"dataset not found at {path}. Run `python scripts/fetch_data.py` first."
        )
    frame = pd.read_csv(path)
    return clean_frame(frame)


def clean_frame(frame: pd.DataFrame) -> pd.DataFrame:
    out = frame.copy()
    if TARGET not in out.columns:
        raise ValueError(f"target column {TARGET!r} is missing")

    out = out.drop_duplicates().reset_index(drop=True)
    out[TARGET] = pd.to_numeric(out[TARGET], errors="coerce").fillna(0).astype(int)
    out = out[out[TARGET].isin([0, 1])]

    for column in RAW_FEATURES:
        out[column] = pd.to_numeric(out[column], errors="coerce").fillna(0).clip(-1, 1)

    out["risk_count_raw"] = (out[RAW_FEATURES] == -1).sum(axis=1)
    out["risk_band"] = pd.cut(
        out["risk_count_raw"],
        bins=[-1, 5, 10, 15, 20, 30],
        labels=["0-5", "6-10", "11-15", "16-20", "21-30"],
    ).astype(str)
    out["ssl_state"] = out["SSLfinal_State"].map({-1: "Phishing-like", 0: "Suspicious", 1: "Valid"}).fillna("Unknown")
    return out.reset_index(drop=True)


def split_data(
    frame: pd.DataFrame,
    test_size: float = TEST_SIZE,
    val_size: float = VAL_SIZE,
    seed: int = RANDOM_STATE,
) -> tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    train, remainder = train_test_split(
        frame,
        test_size=test_size + val_size,
        random_state=seed,
        stratify=frame[TARGET],
    )
    validation, test = train_test_split(
        remainder,
        test_size=test_size / (test_size + val_size),
        random_state=seed,
        stratify=remainder[TARGET],
    )
    return (
        train.reset_index(drop=True),
        validation.reset_index(drop=True),
        test.reset_index(drop=True),
    )


def dataset_summary(frame: pd.DataFrame) -> dict:
    return {
        "rows": len(frame),
        "phishing": int(frame[TARGET].sum()),
        "legitimate": int((1 - frame[TARGET]).sum()),
        "phishing_rate": round(float(frame[TARGET].mean()), 4),
        "features": len(RAW_FEATURES),
        "missing_values": int(frame.isna().sum().sum()),
        "risk_bands": frame["risk_band"].value_counts().sort_index().to_dict(),
        "ssl_states": frame["ssl_state"].value_counts().to_dict(),
        "mean_risk_count": round(float(frame["risk_count_raw"].mean()), 2),
    }


def save_processed(frame: pd.DataFrame, path: str | Path) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    frame.to_csv(path, index=False)
    return path
    template = {}
    for column in frame.columns:
        if column == TARGET:
            continue
        if pd.api.types.is_numeric_dtype(frame[column]):
            value = frame[column].median()
            template[column] = None if pd.isna(value) else float(value)
        else:
            mode = frame[column].mode()
            template[column] = str(mode.iloc[0]) if not mode.empty else "Unknown"
    return template
def median_template(frame: pd.DataFrame) -> dict:
    template = {}
    for column in frame.columns:
        if column == "phishing":
            continue
        if pd.api.types.is_numeric_dtype(frame[column]):
            value = frame[column].median()
            template[column] = None if pd.isna(value) else float(value)
        else:
            mode = frame[column].mode()
            template[column] = str(mode.iloc[0]) if not mode.empty else "Unknown"
    return template
