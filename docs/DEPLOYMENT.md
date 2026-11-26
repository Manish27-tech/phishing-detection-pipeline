# Deployment

## Local

```bash
pip install -e ".[dev]"
python -m phishing.pipeline
streamlit run dashboard/app.py
```

## Docker

```bash
docker build -t phishing-detection .
docker run --rm -p 8501:8501 phishing-detection
```

## GitHub Pages

The static site is published from `docs/` on `main`. Re-run the pipeline after a data or model change and commit `docs/` and `artifacts/` together.

## Retraining checklist

1. Refresh `data/raw/phishing_websites.csv`.
2. Run `python -m phishing.pipeline`.
3. Run `ruff check src tests scripts dashboard`.
4. Run `pytest`.
5. Run `python -m phishing.cli check`.
6. Review feature-group attribution and false-alarm burden.
7. Publish only if calibration and cost are acceptable.

## Monitoring

- Score distribution by risk band.
- Feature-group importance drift.
- False-alarm burden on reviewers.
- Phishing feed freshness.
- Cost ratio changes from abuse-team economics.
