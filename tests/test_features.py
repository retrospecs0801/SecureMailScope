import json
from pathlib import Path

from features import extract_behavioral_features, extract_risk_features

ROOT = Path(__file__).resolve().parents[1]

EXPECTED_RISK_KEYS = {
    "tls_version_ordinal",
    "cipher_is_aead",
    "cipher_is_legacy_weak",
    "key_exchange_has_forward_secrecy",
    "key_exchange_mechanism_cat",
    "cert_available",
    "cert_leaf_expired",
    "cert_leaf_not_yet_valid",
    "cert_leaf_self_signed",
    "cert_chain_complete",
    "cert_issuer_verified",
    "cert_leaf_key_size",
    "cert_leaf_key_algo_cat",
    "cert_leaf_sig_algo_strength",
    "encryption_mode_cat",
    "server_port",
    "port_is_recognized_mail_port",
}

EXPECTED_BEHAVIOR_KEYS = {
    "session_duration_seconds",
    "packet_count",
    "tcp_payload_bytes_c2s",
    "tcp_payload_bytes_s2c",
    "retransmission_count",
    "out_of_order_count",
    "rst_seen",
    "reassembly_fully_complete",
}


def test_risk_feature_schema_is_stable_and_uses_real_fixture_values():
    session = json.loads((ROOT / "capture" / "postfix_tls12_expired_cert.json").read_text(encoding="utf-8"))["sessions"][0]

    features = extract_risk_features(session)
    assert set(features) == EXPECTED_RISK_KEYS
    assert features["cert_leaf_expired"] is True
    assert features["cert_available"] is True

    behavior = extract_behavioral_features(session)
    assert set(behavior) == EXPECTED_BEHAVIOR_KEYS


def test_tls13_synthetic_session_has_unobservable_cert_fields_as_sentinels():
    session = {
        "session_id": "tls13-clean-synthetic",
        "network": {"first_timestamp": "2024-01-01T00:00:00Z", "last_timestamp": "2024-01-01T00:00:05Z", "server": {"port": 993}},
        "encryption": {"value": "implicit_tls"},
        "tls": {
            "negotiated_version": "TLS 1.3",
            "server_hello": {"cipher_suite": {"name": "TLS_AES_128_GCM_SHA256"}},
            "key_exchange": {"forward_secrecy": True, "mechanism": "ECDHE"},
        },
        "certificates": [],
        "certificate_availability": {"value": "encrypted_or_unavailable"},
        "tcp": {
            "packet_count": 12,
            "client_to_server": {"reassembled_bytes": 1000, "retransmissions": 0, "out_of_order": 0, "status": "complete"},
            "server_to_client": {"reassembled_bytes": 900, "retransmissions": 0, "out_of_order": 1, "status": "complete"},
            "rst_seen": False,
        },
    }

    features = extract_risk_features(session)
    assert features["cert_available"] is False
    assert features["cert_leaf_expired"] == -1
    assert features["cert_leaf_not_yet_valid"] == -1
    assert features["cert_leaf_self_signed"] == -1

    behavior = extract_behavioral_features(session)
    assert behavior["reassembly_fully_complete"] is True
    assert behavior["rst_seen"] is False
