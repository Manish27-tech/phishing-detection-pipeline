# Architecture decisions

## 1. Model family

**Decision:** histogram gradient boosting as the default model.
**Reason:** it won the 3-fold PR-AUC comparison with 0.9874 and handles non-linear interactions among heuristic indicators.

## 2. Calibration

**Decision:** isotonic calibration.
**Reason:** risk tiers and thresholding depend on probability accuracy. The test Brier score is 0.0474.

## 3. Cost ratio

**Decision:** weight a missed phishing site 10x more than a false alarm.
**Reason:** missing phishing is more harmful than reviewing a legitimate site. The ratio is configurable and documented in the policy.

## 4. Threshold selection

**Decision:** select on validation, evaluate once on test.
**Reason:** test-set tuning would leak information. The test-optimal threshold is reported but not used.

## 5. Feature groups

**Decision:** aggregate indicators into URL, domain, content and trust families.
**Reason:** individual indicators are numerous and correlated; family attribution is easier to explain to security reviewers.

## 6. Static benchmark

**Decision:** use UCI Phishing Websites and document its limits.
**Reason:** it is public and reproducible, but heuristic indicators are not live page behaviour.

## 7. Raw data in version control

**Decision:** commit the 0.8 MB raw CSV.
**Reason:** the project runs offline and every published number is reproducible.
