# Methodology

## Data

- **Source:** UCI Phishing Websites dataset, 11,055 raw observations (5,849 unique sites) and 30 indicators.
- **Target:** `phishing = 1` if the site is phishing.
- **Cleaning:** convert the UCI target to binary, clip indicators to -1/0/1, remove duplicates and build risk bands.
- **Split:** stratified 70/15/15 train/validation/test with seed 42.

## Feature engineering

- `risk_count`: number of indicators equal to -1.
- `suspicious_count`: number equal to 0.
- `safe_count`: number equal to 1.
- `risk_ratio`: `(risk_count + 0.5 * suspicious_count) / 30`.
- Family counts for URL, domain, content and trust indicators.
- All features are numeric and standard-scaled.

## Model selection

Four candidates are compared with 3-fold stratified cross-validation, ranked by PR-AUC:

1. Logistic regression with balanced class weights.
2. Random forest with balanced subsample weights.
3. Extra trees with balanced weights.
4. Histogram gradient boosting.

Histogram gradient boosting won with CV PR-AUC 0.9874, followed by random forest, extra trees and logistic regression.

## Calibration and policy

- The winning pipeline is calibrated with isotonic regression.
- The threshold is chosen on validation by minimising `10 * missed phishing + 1 * false alarm`.
- The selected threshold is 0.14 on validation, with expected cost 96.92 per 1,000 sites.
- A policy curve reports recall, precision, flagged rate, missed phishing, false alarms and expected cost for every threshold from 0.01 to 0.99.

## Evaluation

- Discrimination: ROC-AUC and PR-AUC.
- Operating point: accuracy, precision, recall, F1, flagged rate, missed phishing, false alarms.
- Probability quality: Brier score and log loss.
- Risk tiers: low, moderate, high, critical.
- Feature-group attribution: URL, domain, content and trust.
- Operational slices by risk band and SSL state.

## Reproducibility

```bash
python scripts/fetch_data.py
python -m phishing.pipeline
python -m phishing.cli check
```

All metrics, figures, predictions and the fitted model are regenerated from `data/raw/phishing_websites.csv`. Checksums are stored in `artifacts/manifest.json`.
