# Results

**Selected model:** hist gradient boosting (isotonic calibration)
**Operating threshold:** 0.14

| Metric | Value |
| --- | ---: |
| ROC-AUC | 0.9855 |
| PR-AUC | 0.9874 |
| Accuracy | 0.8872 |
| Precision | 0.8302 |
| Recall | 0.9823 |
| F1 | 0.8999 |
| Brier | 0.0474 |
| Log loss | 0.1532 |
| Flagged rate | 0.6105 |

Confusion matrix: TN 334 - FP 91 - FN 8 - TP 445.

## Model comparison

| model | pr_auc_mean | pr_auc_std | roc_auc_mean | roc_auc_std |
| --- | --- | --- | --- | --- |
| hist_gradient_boosting | 0.9907 | 0.0004 | 0.9895 | 0.0005 |
| extra_trees | 0.9902 | 0.0012 | 0.9889 | 0.0015 |
| random_forest | 0.9884 | 0.0016 | 0.9864 | 0.0017 |
| logistic_regression | 0.9857 | 0.0004 | 0.9838 | 0.0010 |

## Policy

- Threshold: 0.14
- Cost ratio: 10:1
- Expected cost per 1,000: 97
- Recall: 0.9978
- Precision: 0.8577

## Feature groups

| group | features | importance_mean | importance_std | top_feature |
| --- | --- | --- | --- | --- |
| content | 6 | 0.16840 | 0.01329 | URL_of_Anchor |
| domain | 6 | 0.05076 | 0.00567 | SSLfinal_State |
| url | 6 | 0.01771 | 0.00318 | Prefix_Suffix |
| trust | 12 | 0.01049 | 0.00481 | web_traffic |

## Risk tiers

| tier | sites | phishing | phishing_rate |
| --- | --- | --- | --- |
| Low | 328 | 5 | 1.52% |
| Moderate | 84 | 17 | 20.24% |
| High | 71 | 42 | 59.15% |
| Critical | 395 | 389 | 98.48% |

## Top indicators

| feature | importance_mean | importance_std |
| --- | --- | --- |
| URL_of_Anchor | 0.15614 | 0.00935 |
| SSLfinal_State | 0.04649 | 0.00405 |
| Prefix_Suffix | 0.01594 | 0.00211 |
| SFH | 0.0069 | 0.00223 |
| web_traffic | 0.00535 | 0.0009 |
| Links_in_tags | 0.00347 | 0.00053 |
| having_Sub_Domain | 0.0025 | 0.00061 |
| suspicious_count | 0.0016 | 0.00035 |
| popUpWidnow | 0.00158 | 0.00124 |
| trust_risk_count | 0.00117 | 0.00093 |
| Links_pointing_to_page | 0.00115 | 0.00054 |
| Google_Index | 0.00115 | 0.00037 |
