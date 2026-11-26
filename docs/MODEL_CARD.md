# Model Card - Phishing Website Classifier

## Model details

- **Name:** phishing-detection-pipeline
- **Version:** 0.1.0
- **Type:** hist gradient boosting with isotonic calibration
- **Target:** probability that a website is phishing (`phishing = 1`)
- **Training data:** UCI Phishing Websites, 5,849 sites, 51.62% phishing
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
| ROC-AUC | 0.9855 |
| PR-AUC | 0.9874 |
| Recall | 0.9823 |
| Precision | 0.8302 |
| F1 | 0.8999 |
| Brier | 0.0474 |

## Policy

- Operating threshold: **0.14**
- Cost ratio: **10:1** (missed phishing : false alarm)
- Expected cost per 1,000 sites: **97**

## Feature-group contribution

| group | features | importance_mean | importance_std | top_feature |
| --- | --- | --- | --- | --- |
| content | 6 | 0.16840 | 0.01329 | URL_of_Anchor |
| domain | 6 | 0.05076 | 0.00567 | SSLfinal_State |
| url | 6 | 0.01771 | 0.00318 | Prefix_Suffix |
| trust | 12 | 0.01049 | 0.00481 | web_traffic |

## Limitations

- Heuristic UCI features, not live page content.
- Static dataset; modern phishing changes quickly.
- Cost weights are illustrative.
- No adversarial robustness evaluation.

## Maintenance

Retrain on recent feeds, re-check calibration and feature-group importance, and archive the manifest for every release.
