import pandas as pd

from phishing.data import (
    clean_frame,
    dataset_summary,
    load_raw,
    median_template,
    save_processed,
    split_data,
)


def test_load_raw_has_expected_shape(frame):
    assert len(frame) == 5849
    assert set(frame["phishing"].unique()) == {0, 1}
    assert "risk_band" in frame.columns
    assert "ssl_state" in frame.columns


def test_invalid_feature_is_clipped(sample):
    edited = sample.copy()
    edited.loc[edited.index[0], "URL_Length"] = 99
    edited.loc[edited.index[0], "SSLfinal_State"] = -9
    cleaned = clean_frame(edited)
    assert cleaned.loc[0, "URL_Length"] == 1
    assert cleaned.loc[0, "SSLfinal_State"] == -1


def test_split_sizes_and_stratification(splits):
    train, validation, test = splits
    assert len(train) + len(validation) + len(test) == 5849
    assert len(validation) + 1 >= len(test) >= len(validation) - 1
    rates = [split["phishing"].mean() for split in (train, validation, test)]
    assert max(rates) - min(rates) < 0.01


def test_split_is_deterministic(frame):
    first = split_data(frame)
    second = split_data(frame)
    for left, right in zip(first, second, strict=True):
        assert left.equals(right)


def test_summary_and_template(frame):
    summary = dataset_summary(frame)
    assert summary["rows"] == len(frame)
    assert 0 < summary["phishing_rate"] < 1
    assert summary["missing_values"] == 0
    assert summary["features"] == 30

    template = median_template(frame)
    assert "phishing" not in template
    assert isinstance(template["URL_Length"], float)


def test_save_processed_roundtrip(sample, tmp_path):
    path = save_processed(sample, tmp_path / "processed.csv")
    restored = pd.read_csv(path)
    assert len(restored) == len(sample)
    assert "phishing" in restored.columns


def test_load_raw_rejects_missing_file():
    try:
        load_raw("does-not-exist.csv")
    except FileNotFoundError as error:
        assert "fetch_data" in str(error)
    else:
        raise AssertionError("expected FileNotFoundError")
