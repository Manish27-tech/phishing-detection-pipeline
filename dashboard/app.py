"""Streamlit dashboard for phishing detection.

Run from the repository root:
    streamlit run dashboard/app.py
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pandas as pd
import streamlit as st

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT / "src") not in sys.path:
    sys.path.insert(0, str(ROOT / "src"))

from phishing.evaluate import risk_tier
from phishing.features import model_input
from phishing.model import load_model
from phishing.policy import action_for_tier

ARTIFACTS = ROOT / "artifacts"
FIGURES = ARTIFACTS / "figures"

st.set_page_config(page_title="Phishing Detection", page_icon="🛡️", layout="wide")

st.markdown(
    """
    <style>
    .block-container {padding-top: 2rem; padding-bottom: 3rem;}
    .hero {background: linear-gradient(135deg, #123b4a, #1f6f8b); color: white;
           padding: 26px 30px; border-radius: 16px; margin-bottom: 18px;}
    .hero h1 {margin: 0 0 6px; font-size: 2rem;}
    .hero p {margin: 0; color: #d7eef5; max-width: 900px;}
    </style>
    """,
    unsafe_allow_html=True,
)


@st.cache_data
def load_json(path: str) -> dict:
    return json.loads(Path(path).read_text(encoding="utf-8"))


@st.cache_data
def load_csv(path: str) -> pd.DataFrame:
    return pd.read_csv(path)


@st.cache_resource
def load_assets():
    model = load_model(ARTIFACTS / "phishing_model.joblib")
    template = load_json(str(ARTIFACTS / "dashboard" / "input_template.json"))
    return model, template


def predict_probability(model, template: dict, overrides: dict) -> float:
    row = dict(template)
    row.update(overrides)
    return float(model.predict_proba(model_input(pd.DataFrame([row])))[0, 1])


feed = load_json(str(ARTIFACTS / "dashboard" / "feed.json"))
metrics = feed["metrics"]
summary = feed["summary"]
policy = feed["policy"]
comparison = pd.DataFrame(feed["comparison"])
groups = pd.DataFrame(feed["groups"])
tiers = pd.DataFrame(feed["tiers"])
importance = pd.DataFrame(feed["importance"])
policy_curve = load_csv(str(ARTIFACTS / "policy_curve.csv"))
slices = load_csv(str(ARTIFACTS / "operational_slices.csv"))
model, template = load_assets()

st.markdown(
    f"""
    <div class="hero">
      <h1>🛡️ Phishing Detection Pipeline</h1>
      <p>URL, domain, content and trust indicators from the UCI Phishing Websites benchmark.
      Selected model: <strong>{feed['model'].replace('_', ' ')}</strong>.</p>
    </div>
    """,
    unsafe_allow_html=True,
)

overview, eda, evaluation, simulator, live = st.tabs(
    ["Overview", "Indicator EDA", "Evaluation", "Policy simulator", "Live site"]
)

with overview:
    columns = st.columns(5)
    columns[0].metric("ROC-AUC", f"{metrics['roc_auc']:.3f}")
    columns[1].metric("PR-AUC", f"{metrics['pr_auc']:.3f}")
    columns[2].metric("Phishing recall", f"{metrics['recall']:.1%}")
    columns[3].metric("Precision", f"{metrics['precision']:.1%}")
    columns[4].metric("Cost / 1,000", f"{policy['cost_per_1000']:.0f}")

    st.write(
        f"At threshold **{metrics['threshold']:.2f}**, the model flags **{metrics['flagged_rate']:.1%}** "
        f"of sites, catches **{metrics['recall']:.1%}** of phishing and misses "
        f"**{metrics['missed_phishing']}** of {summary['phishing']} phishing sites in the test set."
    )

    left, right = st.columns([1.05, 1])
    with left:
        st.subheader("Risk tiers")
        view = tiers.copy()
        view["phishing_rate"] = view["phishing_rate"].map(lambda value: f"{value:.1%}")
        st.dataframe(view, use_container_width=True, hide_index=True)
        st.caption("Aggregated indicator counts separate most phishing from legitimate sites.")
    with right:
        st.subheader("Dataset")
        st.write(
            f"{summary['rows']:,} sites - {summary['phishing']:,} phishing - "
            f"{summary['phishing_rate']:.2%} phishing rate"
        )
        st.write(
            "Features cover URL structure, domain properties, page content and trust signals, "
            "plus family-level risk counts."
        )
    st.image(str(FIGURES / "12_risk_tiers.png"), caption="Observed phishing rate by risk tier")

with eda:
    st.subheader("Indicator behaviour")
    stats = pd.DataFrame(
        {
            "metric": ["Sites", "Phishing", "Phishing rate", "Indicators", "Mean risk count", "Missing values"],
            "value": [
                f"{summary['rows']:,}",
                f"{summary['phishing']:,}",
                f"{summary['phishing_rate']:.2%}",
                str(summary["features"]),
                f"{summary['mean_risk_count']:.2f}",
                f"{summary['missing_values']:,}",
            ],
        }
    )
    st.dataframe(stats, use_container_width=True, hide_index=True)
    first, second = st.columns(2)
    first.image(str(FIGURES / "01_class_balance.png"), caption="Class balance")
    second.image(str(FIGURES / "02_risk_count_distribution.png"), caption="Risk-count distribution")
    st.image(str(FIGURES / "03_correlation_heatmap.png"), caption="Correlation structure")
    st.image(str(FIGURES / "04_feature_group_risk.png"), caption="Feature-group risk profile")

with evaluation:
    st.subheader("Model comparison")
    view = comparison.copy()
    for column in ["pr_auc_mean", "pr_auc_std", "roc_auc_mean", "roc_auc_std"]:
        view[column] = view[column].map(lambda value: f"{value:.4f}")
    st.dataframe(view, use_container_width=True, hide_index=True)

    st.subheader("Held-out test metrics")
    metric_table = pd.DataFrame(
        {
            "metric": ["Accuracy", "Precision", "Recall", "F1", "ROC-AUC", "PR-AUC", "Brier", "Flagged rate", "Missed phishing"],
            "value": [
                f"{metrics['accuracy']:.4f}",
                f"{metrics['precision']:.4f}",
                f"{metrics['recall']:.4f}",
                f"{metrics['f1']:.4f}",
                f"{metrics['roc_auc']:.4f}",
                f"{metrics['pr_auc']:.4f}",
                f"{metrics['brier']:.4f}",
                f"{metrics['flagged_rate']:.4f}",
                str(metrics["missed_phishing"]),
            ],
        }
    )
    st.dataframe(metric_table, use_container_width=True, hide_index=True)

    first, second = st.columns(2)
    first.image(str(FIGURES / "06_roc_pr.png"), caption="ROC and precision-recall curves")
    second.image(str(FIGURES / "07_calibration.png"), caption="Reliability diagram")
    third, fourth = st.columns(2)
    third.image(str(FIGURES / "08_confusion_matrix.png"), caption="Confusion matrix")
    fourth.image(str(FIGURES / "09_policy_curve.png"), caption="Cost-sensitive policy")
    st.image(str(FIGURES / "10_feature_importance.png"), caption="Permutation importance")

    st.subheader("Feature groups")
    group_view = groups.copy()
    group_view["importance_mean"] = group_view["importance_mean"].map(lambda value: f"{value:.5f}")
    st.dataframe(group_view, use_container_width=True, hide_index=True)
    st.image(str(FIGURES / "11_feature_group_importance.png"), caption="Feature-group contribution")

    st.subheader("Operational slices")
    st.dataframe(slices, use_container_width=True, hide_index=True)

with simulator:
    st.subheader("Phishing policy simulator")
    st.write(
        "Move the threshold to see the trade-off between missed phishing and false alarms. "
        "A missed phishing site is 10x costlier than a false alarm."
    )
    threshold = st.slider("Probability threshold", min_value=0.01, max_value=0.99, value=float(policy["threshold"]), step=0.01)
    row = policy_curve.iloc[(policy_curve["threshold"] - threshold).abs().argsort()[:1]].iloc[0]
    columns = st.columns(4)
    columns[0].metric("Recall", f"{row['recall']:.1%}")
    columns[1].metric("Precision", f"{row['precision']:.1%}")
    columns[2].metric("Flagged", f"{row['flagged_rate']:.1%}")
    columns[3].metric("Cost / 1,000", f"{row['cost_per_1000']:.0f}")
    st.write(
        f"At threshold **{row['threshold']:.2f}**, **{int(row['missed_phishing'])}** phishing sites are missed "
        f"and **{int(row['false_alarms'])}** legitimate sites are flagged."
    )
    st.line_chart(policy_curve.set_index("threshold")[["recall", "precision", "flagged_rate"]], height=260)
    st.line_chart(policy_curve.set_index("threshold")[["cost_per_1000"]], height=220)

with live:
    st.subheader("Live site assessment")
    st.caption(
        "Adjust the aggregated indicator counts and SSL state; remaining fields use dataset medians. "
        "The score comes from the calibrated model in artifacts/phishing_model.joblib."
    )
    first, second, third = st.columns(3)
    risk_count = first.slider("Phishing-like indicators", min_value=0, max_value=30, value=8)
    suspicious_count = second.slider("Suspicious indicators", min_value=0, max_value=30, value=4)
    ssl_state = third.selectbox("SSL state", ["Valid", "Suspicious", "Phishing-like"], index=0)
    fourth, fifth = st.columns(2)
    url_risk = fourth.slider("URL-family risk count", min_value=0, max_value=6, value=2)
    domain_risk = fifth.slider("Domain-family risk count", min_value=0, max_value=6, value=1)

    overrides = {
        "risk_count": float(risk_count),
        "suspicious_count": float(suspicious_count),
        "safe_count": float(max(0, 30 - risk_count - suspicious_count)),
        "risk_ratio": (risk_count + 0.5 * suspicious_count) / 30,
        "url_risk_count": float(url_risk),
        "domain_risk_count": float(domain_risk),
        "content_risk_count": float(max(0, risk_count - url_risk - domain_risk)),
        "trust_risk_count": float(max(0, risk_count - url_risk - domain_risk)),
        "SSLfinal_State": {"Valid": 1, "Suspicious": 0, "Phishing-like": -1}[ssl_state],
    }
    probability = predict_probability(model, template, overrides)
    tier = risk_tier(probability)
    columns = st.columns(3)
    columns[0].metric("Phishing probability", f"{probability:.1%}")
    columns[1].metric("Risk tier", tier)
    columns[2].metric("Recommended action", action_for_tier(tier))
    st.progress(min(max(probability, 0.0), 1.0))

    scenario = []
    for value in range(0, 31):
        scenario.append(
            {
                "risk_count": value,
                "probability": predict_probability(
                    model,
                    template,
                    {
                        **overrides,
                        "risk_count": float(value),
                        "risk_ratio": (value + 0.5 * suspicious_count) / 30,
                    },
                ),
            }
        )
    st.line_chart(pd.DataFrame(scenario).set_index("risk_count"), height=220)
    st.caption("Score sensitivity to the number of phishing-like indicators.")

    st.warning(
        "Decision support only. A production system needs live URL fetching, allow-list handling, "
        "human review and adversarial robustness testing."
    )
