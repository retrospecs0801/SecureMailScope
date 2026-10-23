import json
from pathlib import Path

from ai_score import score_session

ROOT = Path(__file__).resolve().parents[1]


def test_real_fixture_predicts_critical_with_probabilities_summing_to_one():
    # This is a near-duplicate of a training row, so a passing result here is
    # memorization against the prototype dataset, not evidence of generalization.
    session = json.loads((ROOT / "capture" / "postfix_tls12_expired_cert.json").read_text(encoding="utf-8"))["sessions"][0]

    result = score_session(session)

    assert result["ai_risk_label"] == "critical"
    probs = result["class_probabilities"]
    assert abs(sum(probs.values()) - 1.0) < 1e-6
    assert 0.0 <= result["ai_confidence"] <= 1.0


def test_unknown_categorical_value_does_not_crash_and_returns_valid_output():
    session = json.loads((ROOT / "capture" / "postfix_tls12_expired_cert.json").read_text(encoding="utf-8"))["sessions"][0]
    session["tls"]["key_exchange"]["mechanism"] = "X25519-KEM"
    session["tls"]["server_hello"]["cipher_suite"]["name"] = "TLS_AES_256_GCM_SHA384"

    result = score_session(session)

    assert set(result["class_probabilities"]) == {"low", "moderate", "high", "critical"}
    assert abs(sum(result["class_probabilities"].values()) - 1.0) < 1e-6
    assert 0 <= result["ai_score"] <= 100
