# Phishing Detection Pipeline

[![CI](https://github.com/Manish27-tech/phishing-detection-pipeline/actions/workflows/ci.yml/badge.svg)](https://github.com/Manish27-tech/phishing-detection-pipeline/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](pyproject.toml)

An end-to-end, cost-sensitive phishing website classifier on the UCI Phishing Websites benchmark. It aggregates thirty heuristic indicators into URL, domain, content and trust families, compares four classifiers, calibrates the winner and converts probabilities into a 10:1 cost-sensitive threshold.

**Live results:** https://manish27-tech.github.io/phishing-detection-pipeline/

## Results

| Metric | Value |
| --- | ---: |
| Selected model | Histogram gradient boosting |
| ROC-AUC | 0.9855 |
| PR-AUC | 0.9874 |
| Accuracy | 0.8872 |
| Precision | 0.8302 |
| Recall | 0.9823 |
| F1 | 0.8999 |
| Brier score | 0.0474 |
| Operating threshold | 0.14 |
| Flagged rate | 61.05% |
| Missed phishing | 8 of 453 |
| False alarms | 91 |

Risk tiers on the held-out test set:

| Tier | Sites | Phishing | Observed phishing rate |
| --- | ---: | ---: | ---: |
| Low | 328 | 5 | 1.52% |
| Moderate | 84 | 17 | 20.24% |
| High | 71 | 42 | 59.15% |
| Critical | 395 | 389 | 98.48% |

## Why this project

Phishing triage is a cost-sensitive classification problem: missing a phishing site is more harmful than reviewing a legitimate one. This repository makes that trade-off explicit with calibrated probabilities, a policy curve and feature-group attribution that shows which indicator families drive risk.

## Architecture

```text
data/raw/phishing_websites.csv
        |
        v
clean_frame -> split_data -> risk aggregation
        |
        v
select_model (3-fold CV: logistic, random forest, extra trees, HGB)
        |
        v
calibrate_model (isotonic) -> validation cost policy
        |
        v
test evaluation -> feature-group attribution -> operational slices
        |
        v
artifacts/  reports/  docs/  dashboard/
```

## Project layout

```text
phishing-detection-pipeline/
  src/phishing/          data, features, models, evaluation, policy, plots, reports, pipeline
  dashboard/app.py       Streamlit app with policy simulator and live site assessment
  docs/                  GitHub Pages site, methodology, policy, data dictionary
  reports/               Markdown report and model card
  artifacts/             metrics, figures, predictions, manifest, fitted model
  scripts/fetch_data.py  reproducible OpenML download
  tests/                 35 tests covering data, features, models, evaluation, policy and manifest
```

## Quickstart

```bash
python -m venv .venv
# Windows: .venv\Scripts\activate
source .venv/bin/activate
pip install -e ".[dev]"
python -m phishing.pipeline
streamlit run dashboard/app.py
```

The raw dataset is committed, so the pipeline runs offline. `python scripts/fetch_data.py` re-downloads it for provenance.

## Reproduce the published numbers

```bash
python -m phishing.pipeline
python -m phishing.cli check
ruff check src tests scripts dashboard
pytest
```

Every metric, figure and prediction is regenerated from `data/raw/phishing_websites.csv`. Checksums are stored in `artifacts/manifest.json`.

## Maintenance policy

A missed phishing site is weighted **10x** more heavily than a false alarm.

| Threshold | Recall | Precision | Flagged | Cost / 1,000 |
| ---: | ---: | ---: | ---: | ---: |
| 0.14 (chosen) | 99.78% | 85.77% | 60.09% | 96.92 |
| 0.07 (test-optimal) | 99.34% | 79.37% | 64.58% | 167.43 |

The chosen policy is recall-heavy. The test-optimal threshold is reported but not used.

## Feature-group attribution

| Group | Features | Importance | Top feature |
| --- | ---: | ---: | --- |
| Content | 6 | 0.16840 | URL_of_Anchor |
| Domain | 6 | 0.05076 | SSLfinal_State |
| URL | 6 | 0.01771 | Prefix_Suffix |
| Trust | 12 | 0.01049 | web_traffic |

## Key design choices

- **Histogram gradient boosting** won the 3-fold CV on PR-AUC.
- **Isotonic calibration** makes probabilities usable for risk tiers and thresholding.
- **10:1 cost ratio** reflects the higher cost of missed phishing; the threshold lands at 0.14.
- **Feature-group attribution** keeps 30 correlated indicators explainable to security reviewers.
- **Raw data is committed** so the project runs without network access.

## Dataset

UCI Phishing Websites Dataset. 5,849 unique sites (from 11,055 raw observations), 30 heuristic indicators, 44.3% phishing. Distributed under CC BY 4.0.

> Mohammad, R. M., Thabtah, F. and McCluskey, L. (2015). Phishing Websites Dataset. UCI Machine Learning Repository.

## License

Code is released under the MIT license. See [LICENSE](LICENSE).
