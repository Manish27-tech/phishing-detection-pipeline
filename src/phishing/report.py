"""Markdown reports, model card and static results site."""

from __future__ import annotations

import json
from pathlib import Path

import pandas as pd


def _pct(value: float) -> str:
    return f"{100 * float(value):.2f}%"


def _markdown_table(frame: pd.DataFrame, columns: list[str] | None = None) -> str:
    view = frame[columns] if columns else frame
    header = "| " + " | ".join(str(column) for column in view.columns) + " |"
    divider = "| " + " | ".join("---" for _ in view.columns) + " |"
    rows = [
        "| " + " | ".join("" if pd.isna(value) else str(value) for value in row) + " |"
        for row in view.itertuples(index=False, name=None)
    ]
    return "\n".join([header, divider, *rows])


def _comparison_table(comparison: pd.DataFrame) -> str:
    view = comparison.copy()
    for column in ["pr_auc_mean", "pr_auc_std", "roc_auc_mean", "roc_auc_std"]:
        view[column] = view[column].map(lambda value: f"{value:.4f}")
    return _markdown_table(view)


def _group_table(groups: pd.DataFrame) -> str:
    view = groups.copy()
    view["importance_mean"] = view["importance_mean"].map(lambda value: f"{value:.5f}")
    view["importance_std"] = view["importance_std"].map(lambda value: f"{value:.5f}")
    return _markdown_table(view)


def _tier_table(tiers: pd.DataFrame) -> str:
    view = tiers.copy()
    view["phishing_rate"] = view["phishing_rate"].map(lambda value: _pct(value))
    return _markdown_table(view)


def _slice_table(slices: pd.DataFrame) -> str:
    view = slices.copy()
    for column in ["flag_rate", "recall", "precision", "mean_score"]:
        view[column] = view[column].map(lambda value: "" if pd.isna(value) else f"{value:.4f}")
    return _markdown_table(view)


def write_report(
    *,
    summary: dict,
    split_summary: dict,
    model_name: str,
    comparison: pd.DataFrame,
    policy: dict,
    test_optimal: dict,
    metrics: dict,
    groups: pd.DataFrame,
    slices: pd.DataFrame,
    tiers: pd.DataFrame,
    importance: pd.DataFrame,
    paths: dict[str, Path],
) -> Path:
    top = importance.head(10)
    report = f"""# Phishing Detection Pipeline

**Dataset:** UCI Phishing Websites - {summary['rows']:,} sites, {summary['phishing']:,} phishing ({_pct(summary['phishing_rate'])}).
**Task:** classify a website as phishing from URL, domain, content and trust indicators.
**Operating model:** {model_name.replace('_', ' ')} with isotonic calibration and a cost-sensitive threshold.

## 1. Executive summary

- Test-set **ROC-AUC {metrics['roc_auc']:.4f}**, **PR-AUC {metrics['pr_auc']:.4f}**, **recall {_pct(metrics['recall'])}** and **precision {_pct(metrics['precision'])}**.
- At threshold **{metrics['threshold']:.2f}**, **{_pct(metrics['flagged_rate'])}** of sites are flagged and **{metrics['missed_phishing']}** phishing sites are missed.
- The policy minimises `{policy['fn_cost']:.0f} x missed phishing + {policy['fp_cost']:.0f} x false alarm`, with expected cost **{policy['cost_per_1000']:.0f} per 1,000 sites** on validation.
- URL and domain indicators dominate the feature-group importance, while the site risk-count distribution separates most phishing from legitimate sites.

## 2. Dataset and splits

| Split | Sites | Phishing | Phishing rate |
| --- | ---: | ---: | ---: |
| Train | {split_summary['train_rows']:,} | {split_summary['train_defaults']:,} | {_pct(split_summary['train_rate'])} |
| Validation | {split_summary['val_rows']:,} | {split_summary['val_defaults']:,} | {_pct(split_summary['val_rate'])} |
| Test | {split_summary['test_rows']:,} | {split_summary['test_defaults']:,} | {_pct(split_summary['test_rate'])} |

The split is stratified 70/15/15 with seed 42. Duplicate rows are removed before splitting.

## 3. Method

1. **Cleaning:** convert the UCI target to binary, clip indicators to -1/0/1 and remove duplicates.
2. **Feature engineering:** count phishing-like indicators overall and by URL, domain, content and trust families; add suspicious and safe counts plus a risk ratio.
3. **Preprocessing:** median imputation and standard scaling for all numeric indicators.
4. **Model selection:** 3-fold stratified CV over logistic regression, random forest, extra trees and histogram gradient boosting, ranked by PR-AUC.
5. **Calibration:** isotonic calibration of the winning pipeline.
6. **Thresholding:** validation policy minimises `{policy['fn_cost']:.0f} x missed phishing + {policy['fp_cost']:.0f} x false alarm`.

### Model comparison

{_comparison_table(comparison)}

## 4. Test-set performance

| Metric | Value |
| --- | ---: |
| ROC-AUC | {metrics['roc_auc']:.4f} |
| PR-AUC | {metrics['pr_auc']:.4f} |
| Accuracy | {_pct(metrics['accuracy'])} |
| Precision | {_pct(metrics['precision'])} |
| Recall | {_pct(metrics['recall'])} |
| F1 | {metrics['f1']:.4f} |
| Brier score | {metrics['brier']:.4f} |
| Log loss | {metrics['log_loss']:.4f} |
| Flagged rate | {_pct(metrics['flagged_rate'])} |
| Expected cost | {metrics['cost']:.0f} |

Confusion matrix: TN {metrics['confusion_matrix']['tn']:,}, FP {metrics['confusion_matrix']['fp']:,}, FN {metrics['confusion_matrix']['fn']:,}, TP {metrics['confusion_matrix']['tp']:,}.

Validation chose **{policy['threshold']:.2f}** with expected cost **{policy['cost_per_1000']:.0f} per 1,000**. The test-optimal threshold would be {test_optimal['threshold']:.2f} with cost {test_optimal['cost_per_1000']:.0f}; it is reported, not used.

![ROC and PR curves](figures/06_roc_pr.png)

![Calibration](figures/07_calibration.png)

## 5. Risk tiers

{_tier_table(tiers)}

![Risk tiers](figures/12_risk_tiers.png)

## 6. Feature importance

Top individual indicators:

{_markdown_table(top[['feature', 'importance_mean', 'importance_std']])}

Feature-family contribution:

{_group_table(groups)}

![Feature importance](figures/10_feature_importance.png)

## 7. Operational slices

{_slice_table(slices)}

## 8. Limitations

- UCI features are heuristic indicators, not live URL content or page behaviour.
- The dataset is small and static; modern phishing sites change faster than the indicators.
- Cost weights are illustrative and should come from abuse-team economics.
- The model predicts phishing likelihood, not a legal or safety determination.

## 9. Reproducibility

```bash
python scripts/fetch_data.py
python -m phishing.pipeline
python -m phishing.cli check
streamlit run dashboard/app.py
```

All metrics, figures, predictions and the fitted model are regenerated from `data/raw/phishing_websites.csv`. Checksums are in `artifacts/manifest.json`.

## 10. Next steps

1. Add live URL fetching and HTML feature extraction.
2. Train on recent phishing feeds and measure drift.
3. Add adversarial robustness tests for URL obfuscation.
4. Calibrate the cost model with abuse-team review data.
"""
    path = paths["reports"] / "REPORT.md"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(report, encoding="utf-8")
    return path


def write_model_card(
    *,
    summary: dict,
    model_name: str,
    metrics: dict,
    policy: dict,
    groups: pd.DataFrame,
    paths: dict[str, Path],
) -> Path:
    card = f"""# Model Card - Phishing Website Classifier

## Model details

- **Name:** phishing-detection-pipeline
- **Version:** 0.1.0
- **Type:** {model_name.replace('_', ' ')} with isotonic calibration
- **Target:** probability that a website is phishing (`phishing = 1`)
- **Training data:** UCI Phishing Websites, {summary['rows']:,} sites, {summary['phishing_rate']:.2%} phishing
- **License:** MIT for code; CC BY 4.0 for the dataset

## Intended use

Phishing triage, URL risk scoring and security research on heuristic URL/domain indicators.

## Out-of-scope use

- Blocking decisions without human review or allow-list handling.
- Applying the score to sites whose feature distribution differs materially from UCI.
- Legal determinations of fraud or abuse.

## Inputs

Thirty UCI indicators covering URL structure, domain properties, page content and trust signals, plus eight aggregated risk counts.

## Metrics (held-out test set)

| Metric | Value |
| --- | ---: |
| ROC-AUC | {metrics['roc_auc']:.4f} |
| PR-AUC | {metrics['pr_auc']:.4f} |
| Recall | {metrics['recall']:.4f} |
| Precision | {metrics['precision']:.4f} |
| F1 | {metrics['f1']:.4f} |
| Brier | {metrics['brier']:.4f} |

## Policy

- Operating threshold: **{policy['threshold']:.2f}**
- Cost ratio: **{policy['fn_cost']:.0f}:{policy['fp_cost']:.0f}** (missed phishing : false alarm)
- Expected cost per 1,000 sites: **{policy['cost_per_1000']:.0f}**

## Feature-group contribution

{_group_table(groups)}

## Limitations

- Heuristic UCI features, not live page content.
- Static dataset; modern phishing changes quickly.
- Cost weights are illustrative.
- No adversarial robustness evaluation.

## Maintenance

Retrain on recent feeds, re-check calibration and feature-group importance, and archive the manifest for every release.
"""
    path = paths["reports"] / "MODEL_CARD.md"
    path.write_text(card, encoding="utf-8")
    return path


def write_site(
    *,
    summary: dict,
    model_name: str,
    metrics: dict,
    comparison: pd.DataFrame,
    policy: dict,
    groups: pd.DataFrame,
    tiers: pd.DataFrame,
    importance: pd.DataFrame,
    paths: dict[str, Path],
) -> Path:
    comparison_rows = "".join(
        f"<tr><td>{row.model.replace('_', ' ')}</td><td>{row.pr_auc_mean:.4f}</td><td>{row.roc_auc_mean:.4f}</td></tr>"
        for row in comparison.itertuples()
    )
    group_rows = "".join(
        f"<tr><td>{row.group}</td><td>{row.features}</td><td>{row.importance_mean:.5f}</td><td>{row.top_feature}</td></tr>"
        for row in groups.itertuples()
    )
    tier_rows = "".join(
        f"<tr><td>{row.tier}</td><td>{row.sites:,}</td><td>{row.phishing:,}</td><td>{row.phishing_rate:.2%}</td></tr>"
        for row in tiers.itertuples()
    )
    importance_rows = "".join(
        f"<tr><td>{row.feature}</td><td>{row.importance_mean:.5f}</td><td>{row.importance_std:.5f}</td></tr>"
        for row in importance.head(12).itertuples()
    )
    html = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Phishing Detection Pipeline - Results</title>
<style>
:root {{ color-scheme: light; --ink:#17212b; --muted:#5c6b7a; --accent:#1f6f8b; --bg:#f6f8fa; --card:#fff; --line:#dce3ea; }}
* {{ box-sizing:border-box; }}
body {{ margin:0; font-family:ui-sans-serif,system-ui,-apple-system,Segoe UI,Roboto,sans-serif; color:var(--ink); background:var(--bg); line-height:1.55; }}
header {{ background:linear-gradient(135deg,#123b4a,#1f6f8b); color:#fff; padding:56px 24px; }}
header .wrap, main {{ max-width:1080px; margin:0 auto; }}
h1 {{ margin:0 0 8px; font-size:2.2rem; }}
header p {{ margin:0; color:#d7eef5; max-width:780px; }}
.kpis {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(160px,1fr)); gap:14px; margin:-30px auto 30px; max-width:1080px; padding:0 24px; }}
.kpi {{ background:var(--card); border:1px solid var(--line); border-radius:14px; padding:18px; box-shadow:0 8px 24px rgba(20,40,60,.07); }}
.kpi b {{ display:block; font-size:1.55rem; color:var(--accent); }}
.kpi span {{ color:var(--muted); font-size:.86rem; }}
main {{ padding:0 24px 60px; }}
section {{ background:var(--card); border:1px solid var(--line); border-radius:14px; padding:24px; margin:20px 0; }}
h2 {{ margin-top:0; font-size:1.35rem; }}
table {{ width:100%; border-collapse:collapse; font-size:.92rem; }}
th, td {{ text-align:left; padding:8px 10px; border-bottom:1px solid var(--line); }}
th {{ color:var(--muted); font-weight:600; }}
img {{ width:100%; height:auto; border-radius:10px; border:1px solid var(--line); margin-top:12px; }}
.grid {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(320px,1fr)); gap:16px; }}
a {{ color:var(--accent); }}
code {{ background:#eef3f7; padding:2px 6px; border-radius:5px; }}
footer {{ color:var(--muted); text-align:center; padding:30px 24px 50px; font-size:.86rem; }}
</style>
</head>
<body>
<header><div class="wrap">
<h1>Phishing Detection Pipeline</h1>
<p>URL and domain risk scoring on the UCI Phishing Websites benchmark, with calibrated probabilities, a 10:1 cost-sensitive threshold and feature-group attribution.</p>
</div></header>
<div class="kpis">
<div class="kpi"><b>{metrics['roc_auc']:.3f}</b><span>ROC-AUC</span></div>
<div class="kpi"><b>{metrics['pr_auc']:.3f}</b><span>PR-AUC</span></div>
<div class="kpi"><b>{metrics['recall']:.1%}</b><span>Phishing recall</span></div>
<div class="kpi"><b>{metrics['precision']:.1%}</b><span>Precision</span></div>
<div class="kpi"><b>{policy['cost_per_1000']:.0f}</b><span>Cost per 1,000</span></div>
</div>
<main>
<section>
<h2>What this project demonstrates</h2>
<p>Thirty UCI indicators are aggregated by URL, domain, content and trust families, then modelled with four classifiers. The winner is calibrated and a cost-sensitive threshold is selected on validation. Feature-group attribution shows which indicator families drive risk.</p>
<p><strong>Selected model:</strong> {model_name.replace('_', ' ')} - <strong>Threshold:</strong> {metrics['threshold']:.2f} - <strong>Cost ratio:</strong> {policy['fn_cost']:.0f}:{policy['fp_cost']:.0f}</p>
</section>
<section>
<h2>Model comparison</h2>
<table><thead><tr><th>Model</th><th>CV PR-AUC</th><th>CV ROC-AUC</th></tr></thead><tbody>{comparison_rows}</tbody></table>
<img src="figures/05_model_comparison.png" alt="Model comparison">
</section>
<section>
<h2>Test-set evaluation</h2>
<div class="grid">
<div><img src="figures/06_roc_pr.png" alt="ROC and precision-recall curves"></div>
<div><img src="figures/07_calibration.png" alt="Calibration curve"></div>
</div>
<img src="figures/08_confusion_matrix.png" alt="Confusion matrix">
<img src="figures/09_policy_curve.png" alt="Phishing policy curve">
</section>
<section>
<h2>Risk tiers</h2>
<table><thead><tr><th>Tier</th><th>Sites</th><th>Phishing</th><th>Observed phishing rate</th></tr></thead><tbody>{tier_rows}</tbody></table>
<img src="figures/12_risk_tiers.png" alt="Risk tiers">
</section>
<section>
<h2>Feature groups</h2>
<table><thead><tr><th>Group</th><th>Features</th><th>Importance</th><th>Top feature</th></tr></thead><tbody>{group_rows}</tbody></table>
<img src="figures/11_feature_group_importance.png" alt="Feature-group importance">
</section>
<section>
<h2>Top indicators</h2>
<table><thead><tr><th>Feature</th><th>Mean drop in AP</th><th>Std</th></tr></thead><tbody>{importance_rows}</tbody></table>
<img src="figures/10_feature_importance.png" alt="Permutation importance">
</section>
<section>
<h2>Reproduce</h2>
<p><code>python scripts/fetch_data.py</code><br><code>python -m phishing.pipeline</code><br><code>python -m phishing.cli check</code><br><code>streamlit run dashboard/app.py</code></p>
<p>Full write-up: <a href="RESULTS.md">RESULTS.md</a> - <a href="METHODOLOGY.md">METHODOLOGY.md</a> - <a href="MODEL_CARD.md">MODEL_CARD.md</a></p>
</section>
</main>
<footer>Dataset: UCI Phishing Websites (CC BY 4.0). Code: MIT. Metrics come from a fixed test split; see the manifest for checksums.</footer>
</body>
</html>
"""
    path = paths["docs"] / "index.html"
    path.write_text(html, encoding="utf-8")

    results = f"""# Results

**Selected model:** {model_name.replace('_', ' ')} (isotonic calibration)
**Operating threshold:** {metrics['threshold']:.2f}

| Metric | Value |
| --- | ---: |
| ROC-AUC | {metrics['roc_auc']:.4f} |
| PR-AUC | {metrics['pr_auc']:.4f} |
| Accuracy | {metrics['accuracy']:.4f} |
| Precision | {metrics['precision']:.4f} |
| Recall | {metrics['recall']:.4f} |
| F1 | {metrics['f1']:.4f} |
| Brier | {metrics['brier']:.4f} |
| Log loss | {metrics['log_loss']:.4f} |
| Flagged rate | {metrics['flagged_rate']:.4f} |

Confusion matrix: TN {metrics['confusion_matrix']['tn']:,} - FP {metrics['confusion_matrix']['fp']:,} - FN {metrics['confusion_matrix']['fn']:,} - TP {metrics['confusion_matrix']['tp']:,}.

## Model comparison

{_comparison_table(comparison)}

## Policy

- Threshold: {policy['threshold']:.2f}
- Cost ratio: {policy['fn_cost']:.0f}:{policy['fp_cost']:.0f}
- Expected cost per 1,000: {policy['cost_per_1000']:.0f}
- Recall: {policy['recall']:.4f}
- Precision: {policy['precision']:.4f}

## Feature groups

{_group_table(groups)}

## Risk tiers

{_tier_table(tiers)}

## Top indicators

{_markdown_table(importance.head(12)[['feature', 'importance_mean', 'importance_std']])}
"""
    (paths["docs"] / "RESULTS.md").write_text(results, encoding="utf-8")
    (paths["docs"] / "MODEL_CARD.md").write_text(
        (paths["reports"] / "MODEL_CARD.md").read_text(encoding="utf-8"),
        encoding="utf-8",
    )

    feed = {
        "summary": summary,
        "model": model_name,
        "metrics": metrics,
        "comparison": comparison.to_dict(orient="records"),
        "policy": policy,
        "groups": groups.to_dict(orient="records"),
        "tiers": tiers.to_dict(orient="records"),
        "importance": importance.head(15).to_dict(orient="records"),
    }
    (paths["dashboard"] / "feed.json").write_text(json.dumps(feed, indent=2), encoding="utf-8")
    return path
