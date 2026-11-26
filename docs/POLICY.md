# Policy

## Cost model

A missed phishing site is treated as **10x** costlier than a false alarm:

```text
expected cost = 10 * false negatives + 1 * false positive
```

The ratio is a planning assumption. Replace it with abuse-team review cost and user-harm estimates before deployment.

## Threshold selection

1. Score every validation site with the calibrated model.
2. Compute expected cost for thresholds from 0.01 to 0.99.
3. Choose the threshold with the lowest cost per 1,000 sites.
4. Freeze that threshold and evaluate the test set once.

The selected threshold is **0.14** on validation, with expected cost **96.92 per 1,000** and recall **99.78%**.

## Operating point on test

| Measure | Value |
| --- | ---: |
| Threshold | 0.14 |
| Recall | 98.23% |
| Precision | 83.02% |
| Flagged rate | 61.05% |
| Missed phishing | 8 of 453 |
| False alarms | 91 |
| Expected cost | 171 units |

The test-optimal threshold would be 0.07, but it is not used because tuning on test would leak information.

## Risk tiers

| Tier | Probability | Action |
| --- | --- | --- |
| Low | 0-10% | Allow with normal monitoring |
| Moderate | 10-40% | Review site metadata |
| High | 40-70% | Block or quarantine |
| Critical | 70%+ | Block immediately and investigate |

## Feature-group attribution

Content indicators contribute the most permutation importance, followed by domain, URL and trust indicators. `URL_of_Anchor` is the top individual indicator.

## Limitations

- UCI indicators are heuristic and static.
- Modern phishing changes faster than the dataset.
- Cost weights are illustrative.
- No adversarial robustness testing.

## Review cadence

- Refresh indicators from recent phishing feeds.
- Re-check calibration and feature-group importance.
- Track false-alarm burden on reviewers.
- Update the cost ratio with abuse-team data.
