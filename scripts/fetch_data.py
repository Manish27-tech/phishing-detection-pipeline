"""Download the UCI Phishing Websites dataset via OpenML.

Usage:
    python scripts/fetch_data.py [--force]
"""

from __future__ import annotations

import argparse
from pathlib import Path

import pandas as pd
from sklearn.datasets import fetch_openml

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "data" / "raw" / "phishing_websites.csv"


def fetch(force: bool = False) -> Path:
    if OUTPUT.exists() and not force:
        print(f"already present: {OUTPUT} ({OUTPUT.stat().st_size:,} bytes)")
        return OUTPUT
    frame = fetch_openml(name="PhishingWebsites", version=1, as_frame=True, parser="auto").frame
    frame["phishing"] = (pd.to_numeric(frame["Result"], errors="coerce") == -1).astype(int)
    frame = frame.drop(columns=["Result"])
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    frame.to_csv(OUTPUT, index=False)
    print(f"wrote {OUTPUT} shape={frame.shape}")
    print(f"phishing rate={frame['phishing'].mean():.4f}")
    return OUTPUT


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--force", action="store_true", help="overwrite an existing file")
    arguments = parser.parse_args()
    fetch(arguments.force)
