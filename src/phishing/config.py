"""Configuration for the phishing-detection pipeline."""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

DATA_RAW = ROOT / "data" / "raw" / "phishing_websites.csv"
ARTIFACTS = ROOT / "artifacts"
FIGURES_DIR = ARTIFACTS / "figures"
DASHBOARD_DIR = ARTIFACTS / "dashboard"
MODEL_PATH = ARTIFACTS / "phishing_model.joblib"
MANIFEST_PATH = ARTIFACTS / "manifest.json"

REPORTS_DIR = ROOT / "reports"
REPORT_FIGURES_DIR = REPORTS_DIR / "figures"
DOCS_DIR = ROOT / "docs"
DOCS_FIGURES_DIR = DOCS_DIR / "figures"

RANDOM_STATE = 42
TEST_SIZE = 0.15
VAL_SIZE = 0.15
CV_FOLDS = 3
TARGET = "phishing"

# A missed phishing site is treated as ten times costlier than a false alarm.
FALSE_NEGATIVE_COST = 10.0
FALSE_POSITIVE_COST = 1.0

RISK_TIERS = [
    ("Low", 0.00, 0.10),
    ("Moderate", 0.10, 0.40),
    ("High", 0.40, 0.70),
    ("Critical", 0.70, 1.01),
]

FEATURE_GROUPS = {
    "url": [
        "having_IP_Address",
        "URL_Length",
        "Shortining_Service",
        "having_At_Symbol",
        "double_slash_redirecting",
        "Prefix_Suffix",
    ],
    "domain": [
        "having_Sub_Domain",
        "SSLfinal_State",
        "Domain_registeration_length",
        "Favicon",
        "port",
        "HTTPS_token",
    ],
    "content": [
        "Request_URL",
        "URL_of_Anchor",
        "Links_in_tags",
        "SFH",
        "Submitting_to_email",
        "Abnormal_URL",
    ],
    "trust": [
        "Redirect",
        "on_mouseover",
        "RightClick",
        "popUpWidnow",
        "Iframe",
        "age_of_domain",
        "DNSRecord",
        "web_traffic",
        "Page_Rank",
        "Google_Index",
        "Links_pointing_to_page",
        "Statistical_report",
    ],
}

RAW_FEATURES = [feature for group in FEATURE_GROUPS.values() for feature in group]

ENGINEERED = [
    "risk_count",
    "suspicious_count",
    "safe_count",
    "risk_ratio",
    "url_risk_count",
    "domain_risk_count",
    "content_risk_count",
    "trust_risk_count",
]

NUMERIC_FEATURES = [*RAW_FEATURES, *ENGINEERED]
CATEGORICAL_FEATURES: list[str] = []
FEATURES = [*NUMERIC_FEATURES, *CATEGORICAL_FEATURES]

OPERATIONAL_SLICES = ["risk_band", "ssl_state"]
