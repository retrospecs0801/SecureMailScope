from __future__ import annotations

import json
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.model_selection import LeaveOneOut
import xgboost as xgb

from features import extract_risk_features

ROOT = Path(__file__).resolve().parent
MODEL_DIR = ROOT / "model"
DATASET_PATH = ROOT / "datasets" / "risk_scoring_v1.csv"

LABEL_ORDER = ["low", "moderate", "high", "critical"]
LABEL_TO_INDEX = {label: index for index, label in enumerate(LABEL_ORDER)}
INDEX_TO_LABEL = {index: label for label, index in LABEL_TO_INDEX.items()}
FEATURE_COLUMNS = list(extract_risk_features({}).keys())
CATEGORICAL_COLUMNS = [
    "key_exchange_mechanism_cat",
    "cert_leaf_key_algo_cat",
    "encryption_mode_cat",
]


def _ensure_model_dir() -> None:
    MODEL_DIR.mkdir(parents=True, exist_ok=True)


def _coerce_numeric_series(series: pd.Series) -> pd.Series:
    values = []
    for value in series.tolist():
        if pd.isna(value):
            values.append(np.nan)
            continue
        if isinstance(value, bool):
            values.append(int(value))
            continue
        if isinstance(value, (int, float, np.integer, np.floating)):
            values.append(float(value) if isinstance(value, float) else int(value))
            continue
        text = str(value).strip()
        lowered = text.lower()
        if lowered in {"true", "t", "yes", "y"}:
            values.append(1)
        elif lowered in {"false", "f", "no", "n"}:
            values.append(0)
        elif lowered in {"none", "null", "nan", "na"}:
            values.append(np.nan)
        elif text == "":
            values.append(np.nan)
        else:
            try:
                values.append(float(text))
            except ValueError as exc:
                raise TypeError(f"Unable to coerce non-numeric value {value!r} to a numeric feature") from exc
    return pd.Series(values, index=series.index)


def _validate_numeric_feature_columns(df: pd.DataFrame) -> None:
    for column in FEATURE_COLUMNS:
        if column in CATEGORICAL_COLUMNS:
            continue
        series = df[column]
        if pd.api.types.is_bool_dtype(series) or pd.api.types.is_numeric_dtype(series):
            continue
        raise TypeError(
            "Non-numeric feature detected before encoding; refusing to coerce silently. "
            f"Column: {column}, dtype: {series.dtype}, sample values: {series.dropna().head().tolist()}"
        )


def _build_category_mapping(series: pd.Series) -> dict[str, int]:
    values: list[str] = []
    for value in series.tolist():
        normalized = "unknown"
        if value is not None and not pd.isna(value):
            normalized = str(value).strip()
            if not normalized:
                normalized = "unknown"
        if normalized == "unknown":
            continue
        if normalized not in values:
            values.append(normalized)

    mapping: dict[str, int] = {"unknown": 0}
    for value in values:
        mapping[value] = len(mapping)
    return mapping


def _build_categorical_mappings(df: pd.DataFrame) -> dict[str, dict[str, int]]:
    mappings: dict[str, dict[str, int]] = {}
    for column in CATEGORICAL_COLUMNS:
        mappings[column] = _build_category_mapping(df[column])
    return mappings


def _encode_categorical_columns(df: pd.DataFrame, categorical_mappings: dict[str, dict[str, int]]) -> pd.DataFrame:
    encoded = df.copy()
    for column, mapping in categorical_mappings.items():
        encoded[column] = encoded[column].map(
            lambda value: mapping.get(str(value).strip() if value is not None and not pd.isna(value) and str(value).strip() else "unknown", mapping["unknown"])
        )
    return encoded


def _load_dataset() -> tuple[pd.DataFrame, pd.Series, pd.Series, dict[str, dict[str, int]]]:
    df = pd.read_csv(DATASET_PATH)
    scenario_series = df["scenario_name"].copy()

    if set(FEATURE_COLUMNS) - set(df.columns):
        missing = sorted(set(FEATURE_COLUMNS) - set(df.columns))
        raise ValueError(f"Dataset missing expected feature columns: {missing}")

    df = df.copy()
    for column in FEATURE_COLUMNS:
        if column in CATEGORICAL_COLUMNS:
            continue
        series = df[column]
        if pd.api.types.is_bool_dtype(series) or pd.api.types.is_numeric_dtype(series):
            continue
        df[column] = _coerce_numeric_series(series)
    for column in FEATURE_COLUMNS:
        if column in CATEGORICAL_COLUMNS:
            continue
        df[column] = pd.to_numeric(df[column], errors="raise")
    _validate_numeric_feature_columns(df[FEATURE_COLUMNS])
    categorical_mappings = _build_categorical_mappings(df[FEATURE_COLUMNS])
    encoded_df = _encode_categorical_columns(df[FEATURE_COLUMNS], categorical_mappings)
    X = encoded_df[FEATURE_COLUMNS].copy()
    X = X.apply(pd.to_numeric, errors="raise")
    X = X.astype(float)
    y_raw = df["label"].astype(str).str.strip().str.lower()
    if not set(y_raw.unique()) <= set(LABEL_TO_INDEX):
        unexpected = sorted(set(y_raw.unique()) - set(LABEL_TO_INDEX))
        raise ValueError(f"Unexpected labels in dataset: {unexpected}")
    y = y_raw.map(LABEL_TO_INDEX).astype(int)
    return X, y, scenario_series, categorical_mappings


def _model_parameters(max_depth: int = 2) -> dict[str, object]:
    return {
        "objective": "multi:softprob",
        "num_class": 4,
        "max_depth": max_depth,
        "eta": 0.2,
        "min_child_weight": 1,
        "subsample": 0.9,
        "eval_metric": "mlogloss",
        "seed": 42,
    }


def _fit_model(X_train: pd.DataFrame, y_train: pd.Series, max_depth: int = 2) -> xgb.Booster:
    dtrain = xgb.DMatrix(X_train, label=y_train, feature_names=list(X_train.columns))
    return xgb.train(
        _model_parameters(max_depth),
        dtrain,
        num_boost_round=25,
    )


def _fit_model_from_dmatrix(dtrain: xgb.DMatrix, max_depth: int = 2) -> xgb.Booster:
    return xgb.train(
        _model_parameters(max_depth),
        num_boost_round=25,
        dtrain=dtrain,
    )


def _canonical_probabilities(model: xgb.Booster, X: pd.DataFrame) -> np.ndarray:
    raw = model.predict(xgb.DMatrix(X, feature_names=list(X.columns)))[0]
    return np.asarray(raw, dtype=float)


def _compute_precision_recall(records: list[dict], label_name: str) -> tuple[float, float] | tuple[None, None]:
    if label_name not in LABEL_TO_INDEX:
        return None, None
    true_total = sum(1 for row in records if row["true_label"] == label_name)
    if true_total == 0:
        return None, None
    tp = sum(1 for row in records if row["true_label"] == label_name and row["predicted_label"] == label_name)
    fp = sum(1 for row in records if row["true_label"] != label_name and row["predicted_label"] == label_name)
    fn = sum(1 for row in records if row["true_label"] == label_name and row["predicted_label"] != label_name)
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    return precision, recall


def _run_loocv(X: pd.DataFrame, y: pd.Series, scenario_names: pd.Series) -> tuple[list[dict], dict[str, float], pd.DataFrame]:
    loo = LeaveOneOut()
    records: list[dict] = []
    accuracy_total = 0
    for train_index, test_index in loo.split(X):
        model = _fit_model(X.iloc[train_index], y.iloc[train_index], max_depth=2)
        X_train = X.iloc[train_index].copy()
        y_train = y.iloc[train_index].copy()
        X_test = X.iloc[test_index].copy()
        y_test = y.iloc[test_index].copy()
        probabilities = _canonical_probabilities(model, X_test)
        predicted_index = int(np.argmax(probabilities))
        true_index = int(y_test.iloc[0])
        true_label = INDEX_TO_LABEL[true_index]
        predicted_label = INDEX_TO_LABEL[predicted_index]

        record = {
            "scenario_name": scenario_names.iloc[test_index[0]],
            "true_label": true_label,
            "predicted_label": predicted_label,
            "probability_low": float(probabilities[0]),
            "probability_moderate": float(probabilities[1]),
            "probability_high": float(probabilities[2]),
            "probability_critical": float(probabilities[3]),
            "correct": bool(predicted_index == true_index),
        }
        records.append(record)
        accuracy_total += int(predicted_index == true_index)

    accuracy = accuracy_total / len(records)
    report = {
        "accuracy": accuracy,
        "low_precision": None,
        "low_recall": None,
        "critical_precision": None,
        "critical_recall": None,
    }
    for label_name in ["low", "critical"]:
        precision, recall = _compute_precision_recall(records, label_name)
        if precision is not None and recall is not None:
            report[f"{label_name}_precision"] = precision
            report[f"{label_name}_recall"] = recall

    report_df = pd.DataFrame(records)
    return records, report, report_df


def _run_loocv_depth_comparison(X: pd.DataFrame, y: pd.Series, scenario_names: pd.Series) -> tuple[list[dict], dict[str, float], pd.DataFrame, dict[int, dict[str, float]]]:
    comparison: dict[int, dict[str, float]] = {}
    best: tuple[list[dict], dict[str, float], pd.DataFrame, int] | None = None
    for depth in (2, 3):
        loo = LeaveOneOut()
        records: list[dict] = []
        correct = 0
        for fold_number, (train_index, test_index) in enumerate(loo.split(X)):
            X_train = X.iloc[train_index].copy()
            y_train = y.iloc[train_index].copy()
            X_test = X.iloc[test_index].copy()
            y_test = y.iloc[test_index].copy()
            if depth == 2 and fold_number == 0:
                print("\nDMatrix diagnostic: before construction")
                print(f"X_train.shape={X_train.shape}")
                print(f"X_train.dtype={X_train.dtypes.to_dict()}")
                print(f"X_train[0, :]={X_train.iloc[0].to_numpy()}")
            dtrain = xgb.DMatrix(X_train, label=y_train, feature_names=list(X_train.columns))
            if depth == 2 and fold_number == 0:
                print("DMatrix diagnostic: after construction")
                print(f"dtrain.num_row()={dtrain.num_row()}, dtrain.num_col()={dtrain.num_col()}")
                print(f"fold cache check: X_train_id={id(X_train)}, y_train_id={id(y_train)}, X_test_id={id(X_test)}, y_test_id={id(y_test)}")
            model = _fit_model_from_dmatrix(dtrain, max_depth=depth)
            probabilities = _canonical_probabilities(model, X_test)
            predicted_index = int(np.argmax(probabilities))
            true_index = int(y_test.iloc[0])
            true_label = INDEX_TO_LABEL[true_index]
            predicted_label = INDEX_TO_LABEL[predicted_index]
            correct += int(predicted_index == true_index)
            records.append(
                {
                    "scenario_name": scenario_names.iloc[test_index[0]],
                    "true_label": true_label,
                    "predicted_label": predicted_label,
                    "probability_low": float(probabilities[0]),
                    "probability_moderate": float(probabilities[1]),
                    "probability_high": float(probabilities[2]),
                    "probability_critical": float(probabilities[3]),
                    "correct": bool(predicted_index == true_index),
                }
            )
        accuracy = correct / len(records)
        report = {"accuracy": accuracy}
        for label_name in ["low", "critical"]:
            precision, recall = _compute_precision_recall(records, label_name)
            if precision is not None and recall is not None:
                report[f"{label_name}_precision"] = precision
                report[f"{label_name}_recall"] = recall
        comparison[depth] = report
        if best is None or report["accuracy"] > best[1]["accuracy"]:
            best = (records, report, pd.DataFrame(records), depth)

    if best is None:
        raise RuntimeError("No LOOCV result was produced.")
    return best[0], best[1], best[2], comparison


def _save_loocv_report(report_df: pd.DataFrame, summary: dict[str, float], output_path: Path) -> None:
    comment = (
        "LOOCV results on N=15 — this is a small-sample sanity check, not a production generalization estimate. "
        "See ANALYSIS_DECISIONS.md port-variance note; treat any single-fold misclassification as informative, not alarming, "
        "given the sample size."
    )
    report_with_metadata = report_df.copy()
    report_with_metadata.insert(0, "report_comment", comment)
    report_with_metadata["aggregate_accuracy"] = summary["accuracy"]
    report_with_metadata.to_csv(output_path, index=False)


def main() -> None:
    _ensure_model_dir()
    X, y, scenario_names, categorical_mappings = _load_dataset()

    records, summary, report_df, comparison = _run_loocv_depth_comparison(X, y, scenario_names)
    print("=" * 80)
    print("LOOCV results on N=15 — this is a small-sample sanity check, not a production generalization estimate.")
    print("See ANALYSIS_DECISIONS.md port-variance note; treat any single-fold misclassification as informative, not alarming, given the sample size.")
    print("=" * 80)
    print(f"Accuracy (max_depth=2): {comparison[2]['accuracy']:.3f}")
    print(f"Accuracy (max_depth=3): {comparison[3]['accuracy']:.3f}")
    print("\nPer-row LOOCV table:")
    print(report_df.to_string(index=False))

    # Print class metrics for labels actually present in the dataset.
    print("\nPer-class metrics for currently observed labels:")
    for label in ["low", "critical"]:
        if label in y.map(INDEX_TO_LABEL).values:
            precision, recall = _compute_precision_recall(records, label)
            print(f"{label}: precision={precision if precision is not None else 'n/a'}, recall={recall if recall is not None else 'n/a'}")
        else:
            print(f"{label}: no examples in current dataset")

    print(f"\nAggregate LOOCV accuracy: {summary['accuracy']:.3f}")
    _save_loocv_report(report_df, summary, MODEL_DIR / "loocv_report_v1.csv")

    label_mapping_path = MODEL_DIR / "label_mapping.json"
    label_mapping_path.write_text(json.dumps(LABEL_TO_INDEX, indent=2), encoding="utf-8")

    categorical_mapping_path = MODEL_DIR / "categorical_mappings.json"
    categorical_mapping_path.write_text(json.dumps(categorical_mappings, indent=2), encoding="utf-8")

    dtrain_full = xgb.DMatrix(X, label=y, feature_names=list(X.columns))
    final_model = _fit_model_from_dmatrix(dtrain_full, max_depth=2)
    final_model.save_model(str(MODEL_DIR / "ai_risk_model.json"))

    print("\nBaseline full-data fit feature importance (weight):")
    print(final_model.get_score(importance_type="weight"))

    importance_df = pd.DataFrame(
        {
            "feature": X.columns.tolist(),
            "importance": [float(final_model.get_score(importance_type="gain").get(column, 0.0)) for column in X.columns],
        }
    ).sort_values("importance", ascending=False)
    importance_df.to_csv(MODEL_DIR / "feature_importance.csv", index=False)

    print("\nFeature importance ranking:")
    print(importance_df.to_string(index=False))

    server_port_importance = float(importance_df.loc[importance_df["feature"] == "server_port", "importance"].iloc[0]) if "server_port" in importance_df["feature"].values else 0.0
    recognized_port_importance = float(importance_df.loc[importance_df["feature"] == "port_is_recognized_mail_port", "importance"].iloc[0]) if "port_is_recognized_mail_port" in importance_df["feature"].values else 0.0
    print(
        "\nPort-feature importance check: "
        f"server_port={server_port_importance:.12f}, "
        f"port_is_recognized_mail_port={recognized_port_importance:.12f}. "
        "This is expected to be near zero because the dataset has zero variance on port features."
    )
    if server_port_importance > 1e-3 or recognized_port_importance > 1e-3:
        raise RuntimeError(
            "BUG: port features show meaningful feature importance despite zero variance in the dataset; "
            "this indicates a leakage/encoding issue that must be investigated before deployment."
        )

    print("\nSaved model artifacts to:", MODEL_DIR)


if __name__ == "__main__":
    main()
