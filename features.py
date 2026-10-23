"""Feature extraction for raw parser sessions.

Schema contract for the training pipeline:

Feature name          Type     Meaning / sentinel
--------------------  -------  ------------------------------------------------------
tls_version_ordinal   int      SSL3.0=0, TLS1.0=1, TLS1.1=2, TLS1.2=3, TLS1.3=4, unknown=-1
cipher_is_aead       int/bool -1 if cipher unavailable/unmapped; otherwise bool
cipher_is_legacy_weak int/bool -1 if cipher unavailable/unmapped; otherwise bool
key_exchange_has_forward_secrecy int 1/0 for known value, -1 if unknown
key_exchange_mechanism_cat str  ECDHE/DHE/RSA/unknown
cert_available       bool     True iff certificate_availability.value == "available"
cert_leaf_expired    int/bool -1 when cert_available is False; otherwise bool
cert_leaf_not_yet_valid int/bool -1 when cert_available is False; otherwise bool
cert_leaf_self_signed int/bool -1 when cert_available is False; otherwise bool
cert_chain_complete  int/bool -1 when cert_available is False; otherwise bool
cert_issuer_verified int/bool -1 when cert_available is False; otherwise bool
cert_leaf_key_size   int      public_key_size or -1 if unavailable
cert_leaf_key_algo_cat str    RSA/EC/unknown or "unavailable" when cert is not available
cert_leaf_sig_algo_strength int 0 critical, 1 high, 2 low, -1 unavailable/unmapped
encryption_mode_cat  str      STARTTLS/implicit_tls/none/unknown from encryption.value
server_port          int      network.server.port or -1 if missing
port_is_recognized_mail_port bool True when port is in {25,110,143,465,587,993,995}

Keep this table in sync manually with the code below until a shared schema file exists.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from analyzer.analysis import OID_NAMES

_RECOGNIZED_MAIL_PORTS = {25, 110, 143, 465, 587, 993, 995}
_TLS_VERSION_ORDINAL = {
    "SSL 3.0": 0,
    "SSL3.0": 0,
    "TLS 1.0": 1,
    "TLS1.0": 1,
    "TLS 1.1": 2,
    "TLS1.1": 2,
    "TLS 1.2": 3,
    "TLS1.2": 3,
    "TLS 1.3": 4,
    "TLS1.3": 4,
}


def _as_int(value: Any, default: int = -1) -> int:
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.strip().isdigit():
        return int(value)
    return default


def _parse_iso8601(value: Any) -> datetime | None:
    if not value:
        return None
    if isinstance(value, datetime):
        return value
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None


def extract_risk_features(session: dict) -> dict:
    """
    Extracts features for AI-based cryptographic risk scoring.
    Reads RAW parser fields only (tls.*, certificates[], network.*, encryption.*) —
    MUST NOT read anything from analysis.py's findings/deterministic_score output.
    """
    tls = session.get("tls", {}) or {}
    network = session.get("network", {}) or {}
    encryption = session.get("encryption", {}) or {}
    certificate_availability = session.get("certificate_availability", {}) or {}

    tls_version = str(tls.get("negotiated_version", "unknown"))
    tls_version_ordinal = _TLS_VERSION_ORDINAL.get(tls_version, -1)

    cipher_name = str((tls.get("server_hello", {}) or {}).get("cipher_suite", {}).get("name", "UNKNOWN"))
    upper = cipher_name.upper()
    if cipher_name in {"", "UNKNOWN", "None", "null"}:
        cipher_is_aead = -1
        cipher_is_legacy_weak = -1
    else:
        cipher_is_aead = bool(any(token in upper for token in ("GCM", "POLY1305", "CCM")))
        cipher_is_legacy_weak = bool(any(token in upper for token in ("RC4", "3DES", "NULL", "EXPORT", "ANON", "DES")))

    key_exchange = tls.get("key_exchange", {}) or {}
    raw_forward_secrecy = key_exchange.get("forward_secrecy", "unknown")
    if raw_forward_secrecy is True:
        key_exchange_has_forward_secrecy = 1
    elif raw_forward_secrecy is False:
        key_exchange_has_forward_secrecy = 0
    else:
        key_exchange_has_forward_secrecy = -1
    key_exchange_mechanism = str(key_exchange.get("mechanism", "unknown")).strip() or "unknown"
    key_exchange_mechanism_cat = key_exchange_mechanism if key_exchange_mechanism in {"ECDHE", "DHE", "RSA", "unknown"} else "unknown"

    cert_available = certificate_availability.get("value") == "available"
    certificates = session.get("certificates") or []
    leaf = certificates[0] if certificates else {}
    validation = leaf.get("validation", {}) if isinstance(leaf, dict) else {}
    if cert_available:
        cert_leaf_expired = bool(validation.get("expired") is True)
        cert_leaf_not_yet_valid = bool(validation.get("not_yet_valid") is True)
        cert_leaf_self_signed = bool(validation.get("self_signed") is True)
        cert_chain_complete = bool(validation.get("observed_chain_complete") is True)
        cert_issuer_verified = bool(validation.get("issuer_relationship_verified") is True)
    else:
        cert_leaf_expired = -1
        cert_leaf_not_yet_valid = -1
        cert_leaf_self_signed = -1
        cert_chain_complete = -1
        cert_issuer_verified = -1

    cert_leaf_key_size = -1
    cert_leaf_key_algo_cat = "unavailable" if not cert_available else "unknown"
    if isinstance(leaf, dict):
        key_size = leaf.get("public_key_size")
        if isinstance(key_size, int):
            cert_leaf_key_size = key_size
        algorithm = str(leaf.get("public_key_algorithm", "")).strip()
        if cert_available:
            if "RSA" in algorithm.upper():
                cert_leaf_key_algo_cat = "RSA"
            elif any(token in algorithm.upper() for token in ("EC", "ECDSA", "ELLIPTIC")):
                cert_leaf_key_algo_cat = "EC"
            else:
                cert_leaf_key_algo_cat = "unknown"

    oid = str(leaf.get("signature_algorithm", "")) if isinstance(leaf, dict) else ""
    cert_leaf_sig_algo_strength = -1
    if cert_available and oid:
        name = OID_NAMES.get(oid)
        if name:
            lower = name.lower()
            if "md5" in lower:
                cert_leaf_sig_algo_strength = 0
            elif "sha1" in lower:
                cert_leaf_sig_algo_strength = 1
            elif any(token in lower for token in ("sha256", "sha384", "sha512")):
                cert_leaf_sig_algo_strength = 2

    encryption_mode = str(encryption.get("value", "unknown"))
    server_port = _as_int((network.get("server", {}) or {}).get("port", -1), default=-1)
    port_is_recognized_mail_port = server_port in _RECOGNIZED_MAIL_PORTS

    return {
        "tls_version_ordinal": tls_version_ordinal,
        "cipher_is_aead": cipher_is_aead,
        "cipher_is_legacy_weak": cipher_is_legacy_weak,
        "key_exchange_has_forward_secrecy": key_exchange_has_forward_secrecy,
        "key_exchange_mechanism_cat": key_exchange_mechanism_cat,
        "cert_available": bool(cert_available),
        "cert_leaf_expired": cert_leaf_expired,
        "cert_leaf_not_yet_valid": cert_leaf_not_yet_valid,
        "cert_leaf_self_signed": cert_leaf_self_signed,
        "cert_chain_complete": cert_chain_complete,
        "cert_issuer_verified": cert_issuer_verified,
        "cert_leaf_key_size": cert_leaf_key_size,
        "cert_leaf_key_algo_cat": cert_leaf_key_algo_cat,
        "cert_leaf_sig_algo_strength": cert_leaf_sig_algo_strength,
        "encryption_mode_cat": encryption_mode or "unknown",
        "server_port": server_port,
        "port_is_recognized_mail_port": bool(port_is_recognized_mail_port),
    }


def extract_behavioral_features(session: dict) -> dict:
    """
    Extracts features for unsupervised anomaly detection: timing, packet-size,
    and protocol-behavior signal that extract_risk_features() does not include.
    """
    network = session.get("network", {}) or {}
    tcp = session.get("tcp", {}) or {}

    first_ts = _parse_iso8601(network.get("first_timestamp"))
    last_ts = _parse_iso8601(network.get("last_timestamp"))
    if first_ts and last_ts:
        session_duration_seconds = max(0.0, (last_ts - first_ts).total_seconds())
    else:
        session_duration_seconds = 0.0

    packet_count = _as_int(tcp.get("packet_count"), default=0)
    c2s = tcp.get("client_to_server", {}) or {}
    s2c = tcp.get("server_to_client", {}) or {}
    c2s_bytes = _as_int(c2s.get("reassembled_bytes"), default=0)
    s2c_bytes = _as_int(s2c.get("reassembled_bytes"), default=0)
    retransmission_count = _as_int(c2s.get("retransmissions"), default=0) + _as_int(s2c.get("retransmissions"), default=0)
    out_of_order_count = _as_int(c2s.get("out_of_order"), default=0) + _as_int(s2c.get("out_of_order"), default=0)
    rst_seen = bool(tcp.get("rst_seen") is True or c2s.get("rst_seen") is True or s2c.get("rst_seen") is True)
    reassembly_fully_complete = bool(c2s.get("status") == "complete" and s2c.get("status") == "complete")

    # JA3/JA3S fingerprint and packet-size-distribution features are planned but not yet available — parser.py does not currently extract them.
    # Add here once the parser supports fingerprinting (see architecture doc).
    return {
        "session_duration_seconds": session_duration_seconds,
        "packet_count": packet_count,
        "tcp_payload_bytes_c2s": c2s_bytes,
        "tcp_payload_bytes_s2c": s2c_bytes,
        "retransmission_count": retransmission_count,
        "out_of_order_count": out_of_order_count,
        "rst_seen": rst_seen,
        "reassembly_fully_complete": reassembly_fully_complete,
    }
