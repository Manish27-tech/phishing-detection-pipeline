"""Shared fixtures for the phishing test suite."""

from __future__ import annotations

import sys
from pathlib import Path

import pandas as pd
import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT / "src") not in sys.path:
    sys.path.insert(0, str(ROOT / "src"))

from phishing.data import load_raw, split_data


@pytest.fixture(scope="session")
def frame():
    return load_raw()


@pytest.fixture(scope="session")
def splits(frame):
    return split_data(frame)


@pytest.fixture(scope="session")
def sample(frame):
    phishing = frame[frame["phishing"] == 1]
    legitimate = frame[frame["phishing"] == 0].head(1000)
    return (
        pd.concat([phishing, legitimate])
        .sample(frac=1, random_state=42)
        .reset_index(drop=True)
    )
