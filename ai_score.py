from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd
import xgboost as xgb

from features import extract_risk_features

ROOT = Path(__file__).resolve().parent
MODEL_DIR = ROOT / "model"

LABEL_ORDER = ["low", "moderate", "high", "critical"]
LABEL_TO_INDEX = {label: idx for idx, label in enumerate(LABEL_ORDER)}
INDEX_TO_LABEL = {idx: label for label, idx in LABEL_TO_INDEX.items()}
CLASS_MIDPOINTS = {"low": 12.5, "moderate": 37.5, "high": 62.5, "critical": 87.5}
CATEGORICAL_COLUMNS = ["key_exchange_mechanism_cat", "cert_leaf_key_algo_cat", "encryption_mode_cat"]


@lru_cache(maxsize=1)
def _load_model_bundle() -> dict[str, Any]:
    if not MODEL_DIR.exists():
        raise FileNotFoundError("Model directory does not exist. Train the AI model before calling score_session().")

    label_map_path = MODEL_DIR / "label_mapping.json"
    cat_map_path = MODEL_DIR / "categorical_mappings.json"
    model_path = MODEL_DIR / "ai_risk_model.json"

    for path in (label_map_path, cat_map_path, model_path):
        if not path.exists():
            raise FileNotFoundError(f"Missing model artifact: {path}")

    with label_map_path.open("r", encoding="utf-8") as handle:
        label_mapping = json.load(handle)
    with cat_map_path.open("r", encoding="utf-8") as handle:
        categorical_mappings = json.load(handle)

    expected_mapping = {label: index for index, label in enumerate(LABEL_ORDER)}
    if label_mapping != expected_mapping:
        raise ValueError(f"Unsafe label mapping: {label_mapping!r}")

    model = xgb.Booster()
    model.load_model(str(model_path))
    return {
        "label_mapping": label_mapping,
        "categorical_mappings": categorical_mappings,
        "model": model,
    }


def _normalize_category(value: Any, mapping: dict[str, int]) -> int:
    if value is None or pd.isna(value):
        return int(mapping.get("unknown", 0))
    text = str(value).strip()
    if not text:
        return int(mapping.get("unknown", 0))
    return int(mapping.get(text, mapping.get("unknown", 0)))


def _convert_feature_value(value: Any) -> Any:
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, (int, float, np.integer, np.floating)):
        return value
    if value is None:
        return None
    if isinstance(value, str):
        stripped = value.strip()
        if stripped == "":
            return None
        try:
            return int(stripped)
        except ValueError:
            try:
                return float(stripped)
            except ValueError:
                return stripped
    return value


def _build_feature_frame(raw_session: dict) -> pd.DataFrame:
    bundle = _load_model_bundle()
    features = extract_risk_features(raw_session)
    encoded: dict[str, Any] = {}
    for key, value in features.items():
        if key in CATEGORICAL_COLUMNS:
            mapping = bundle["categorical_mappings"].get(key, {"unknown": 0})
            encoded[key] = _normalize_category(value, mapping)
        else:
            encoded[key] = _convert_feature_value(value)

    feature_order = list(extract_risk_features({}).keys())
    ordered_row = {name: encoded.get(name, -1) for name in feature_order}
    return pd.DataFrame([ordered_row]).astype(float)


def score_session(session: dict) -> dict:
    """
    Takes a RAW parsed session dict and returns a probability-weighted AI risk score.
    """
    bundle = _load_model_bundle()
    model = bundle["model"]
    label_mapping = bundle["label_mapping"]

    X = _build_feature_frame(session)
    probabilities = np.asarray(model.predict(xgb.DMatrix(X, feature_names=list(X.columns)))[0], dtype=float)
    if probabilities.shape[0] != 4:
        raise ValueError(f"Expected 4-class probabilities, received shape {probabilities.shape}.")

    class_probabilities = {
        "low": float(probabilities[0]),
        "moderate": float(probabilities[1]),
        "high": float(probabilities[2]),
        "critical": float(probabilities[3]),
    }
    mapped_label_index = int(np.argmax(probabilities))
    predicted_label = INDEX_TO_LABEL.get(mapped_label_index, "low")
    if predicted_label not in label_mapping:
        predicted_label = "low"

    ai_score = round(
        sum(class_probabilities[label] * CLASS_MIDPOINTS[label] for label in LABEL_ORDER)
    )
    ai_confidence = float(np.max(probabilities))

    return {
        "ai_score": int(max(0, min(100, ai_score))),
        "ai_risk_label": predicted_label,
        "ai_confidence": ai_confidence,
        "class_probabilities": {
            "low": float(class_probabilities["low"]),
            "moderate": float(class_probabilities["moderate"]),
            "high": float(class_probabilities["high"]),
            "critical": float(class_probabilities["critical"]),
        },
    }
