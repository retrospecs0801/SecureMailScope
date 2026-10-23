import json
from pathlib import Path

from analyzer.analysis import analyze_session
from scripts.run_tls_scenario import SCENARIOS


ROOT = Path(__file__).resolve().parents[1]


def test_expired_fixture_produces_expected_findings():
    data = json.loads((ROOT / "capture" / "postfix_tls12_expired_cert.json").read_text(encoding="utf-8"))
    result = analyze_session(data["sessions"][0])
    findings = {finding["check"]: finding for finding in result["findings"]}

    assert result["confidence"]["level"] in {"medium", "low"}
    assert result["confidence"]["reasons"]
    assert any(token in " ".join(result["confidence"]["reasons"]) for token in ("partial", "rst"))
    assert findings["certificate_validity[0]"]["risk_level"] == "critical"
    assert "expired" in findings["certificate_validity[0]"]["rationale"].lower()
    assert findings["certificate_validity[1]"]["risk_level"] != "critical"
    assert findings["tls_version"]["risk_level"] == "moderate"
    assert findings["cipher_suite"]["risk_level"] == "low"
    assert findings["encryption_transition"]["risk_level"] == "moderate"
    assert "nonstandard" in findings["encryption_transition"]["rationale"]
    assert result["deterministic_risk"] == "critical"


def test_expired_variant_scenarios_are_defined_and_critical():
    for name in ("tls12_expired_ecdsa", "tls12_expired_rsa4096", "tls12_expired_weak_sig"):
        assert name in SCENARIOS
        assert SCENARIOS[name].label == "critical"


def test_tls13_encrypted_certificates_are_not_penalized():
    session = {
        "session_id": "tls13-clean",
        "network": {"server": {"port": 993}},
        "email_protocol": {"confidence": "high", "value": "IMAP"},
        "encryption": {"confidence": "high", "value": "implicit_tls"},
        "certificate_availability": {"confidence": "high", "value": "encrypted_or_unavailable"},
        "tcp": {"client_to_server": {"status": "complete"}, "server_to_client": {"status": "complete"}, "rst_seen": False},
        "tls": {
            "negotiated_version": "TLS 1.3",
            "handshake_completion_status": "observed",
            "server_hello": {"cipher_suite": {"id": "0x1302", "name": "TLS_AES_256_GCM_SHA384"}},
            "key_exchange": {"mechanism": "ECDHE", "forward_secrecy": True},
        },
        "certificates": [],
    }
    result = analyze_session(session)
    assert not any(finding["check"].startswith(("certificate_", "public_key_", "signature_")) for finding in result["findings"])
    assert result["deterministic_risk"] == "low"


def test_nonstandard_port_does_not_floor_clean_session():
    session = {
        "session_id": "tls13-clean-nonstandard-port",
        "network": {"server": {"port": 2525}},
        "email_protocol": {"confidence": "high", "value": "SMTP"},
        "encryption": {"confidence": "high", "value": "implicit_tls"},
        "certificate_availability": {"confidence": "high", "value": "encrypted_or_unavailable"},
        "tcp": {"client_to_server": {"status": "complete"}, "server_to_client": {"status": "complete"}, "rst_seen": False},
        "tls": {
            "negotiated_version": "TLS 1.3",
            "handshake_completion_status": "observed",
            "server_hello": {"cipher_suite": {"id": "0x1302", "name": "TLS_AES_256_GCM_SHA384"}},
            "key_exchange": {"mechanism": "ECDHE", "forward_secrecy": True},
        },
        "certificates": [],
    }
    result = analyze_session(session)
    transition = {finding["check"]: finding for finding in result["findings"]}["encryption_transition"]
    assert transition["risk_level"] == "moderate"
    assert transition["contributes_to_score"] is False
    assert result["deterministic_risk"] == "low"


def test_plaintext_on_implicit_tls_port_still_critical():
    session = {
        "session_id": "plaintext-on-993",
        "network": {"server": {"port": 993}},
        "email_protocol": {"confidence": "high", "value": "IMAP"},
        "encryption": {"confidence": "high", "value": "none"},
        "certificate_availability": {"confidence": "high", "value": "unavailable"},
        "tcp": {"packet_count": 12, "client_to_server": {"status": "complete", "reassembled_bytes": 200, "retransmissions": 0, "out_of_order": 0}, "server_to_client": {"status": "complete", "reassembled_bytes": 120, "retransmissions": 0, "out_of_order": 0}, "rst_seen": False},
        "tls": {
            "negotiated_version": "unknown",
            "handshake_completion_status": "not_observed",
            "server_hello": {"cipher_suite": {"id": "unknown", "name": "UNKNOWN"}},
            "key_exchange": {"mechanism": "unknown", "forward_secrecy": "unknown"},
        },
        "certificates": [],
    }
    result = analyze_session(session)
    assert result["deterministic_risk"] == "critical"
    assert result["deterministic_score"] == 100