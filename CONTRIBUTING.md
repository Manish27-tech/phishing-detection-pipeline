# Contributing

Thanks for looking at the phishing-detection pipeline.

## Setup

```bash
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
python -m phishing.pipeline
streamlit run dashboard/app.py
```

## Checks

```bash
ruff check src tests scripts dashboard
pytest
python -m phishing.cli check
```

## Guidelines

- Keep indicators in their UCI -1/0/1 encoding.
- Add derived risk counts in `features.py`.
- Do not tune the threshold on the test split.
- Update `docs/POLICY.md` if the cost ratio changes.
- Commit generated artifacts with the code that produced them.
