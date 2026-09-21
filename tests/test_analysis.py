import json
from pathlib import Path

from analyzer.analysis import analyze_session


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