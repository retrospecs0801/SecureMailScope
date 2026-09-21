#!/usr/bin/env python3
"""Passive SMTP/IMAP/POP3 and TLS forensic extraction from PCAP/PCAPNG files.

The parser deliberately does no scoring, recommendations, decryption, or trust-store
evaluation.  It reports what was observed, and retains partial-stream uncertainty.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
from collections import defaultdict
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dsa, ec, padding, rsa
from cryptography.x509.oid import ExtensionOID
from scapy.layers.inet import IP, TCP
from scapy.layers.inet6 import IPv6
from scapy.utils import PcapReader

LOG = logging.getLogger(__name__)
SCHEMA_VERSION = "1.0"

CIPHER_SUITES: dict[int, str] = {
    0x0000: "TLS_NULL_WITH_NULL_NULL",
    0x002F: "TLS_RSA_WITH_AES_128_CBC_SHA",
    0x0035: "TLS_RSA_WITH_AES_256_CBC_SHA",
    0x009C: "TLS_RSA_WITH_AES_128_GCM_SHA256",
    0x009D: "TLS_RSA_WITH_AES_256_GCM_SHA384",
    0xC02F: "ECDHE-RSA-AES128-GCM-SHA256",
    0xC030: "ECDHE-RSA-AES256-GCM-SHA384",
    0xC02B: "ECDHE-ECDSA-AES128-GCM-SHA256",
    0xC02C: "ECDHE-ECDSA-AES256-GCM-SHA384",
    0x1301: "TLS_AES_128_GCM_SHA256",
    0x1302: "TLS_AES_256_GCM_SHA384",
    0x1303: "TLS_CHACHA20_POLY1305_SHA256",
}
TLS_VERSIONS = {0x0300: "SSL 3.0", 0x0301: "TLS 1.0", 0x0302: "TLS 1.1", 0x0303: "TLS 1.2", 0x0304: "TLS 1.3"}
GROUPS = {23: "secp256r1", 24: "secp384r1", 25: "secp521r1", 29: "x25519", 30: "x448", 256: "ffdhe2048", 257: "ffdhe3072"}
HANDSHAKES = {1: "ClientHello", 2: "ServerHello", 4: "NewSessionTicket", 8: "EncryptedExtensions", 11: "Certificate", 12: "ServerKeyExchange", 13: "CertificateRequest", 14: "ServerHelloDone", 15: "CertificateVerify", 16: "ClientKeyExchange", 20: "Finished"}


@dataclass(frozen=True, order=True)
class Endpoint:
    address: str
    port: int


@dataclass(frozen=True)
class FlowKey:
    left: Endpoint
    right: Endpoint
    protocol: str = "TCP"

    @classmethod
    def canonical(cls, source: Endpoint, destination: Endpoint) -> "FlowKey":
        return cls(*sorted((source, destination)), "TCP")


@dataclass
class Evidence:
    value: str
    confidence: str
    evidence: list[str]
    frames: list[int] = field(default_factory=list)


@dataclass
class Segment:
    sequence: int
    payload: bytes
    frame: int
    timestamp: float
    flags: str


@dataclass
class ReassembledStream:
    data: bytes
    status: str
    missing_ranges: list[dict[str, int]]
    retransmissions: int
    out_of_order: int
    duplicate_segments: int
    fin_seen: bool
    rst_seen: bool
    frames: list[int]


class TCPDirection:
    """Stores a direction's packets and deterministically rebuilds contiguous bytes."""

    def __init__(self) -> None:
        self.segments: list[Segment] = []
        self._seen: set[tuple[int, bytes]] = set()
        self.retransmissions = 0
        self.duplicates = 0
        self.out_of_order = 0
        self._largest_end: Optional[int] = None
        self.fin_seen = False
        self.rst_seen = False
        self.truncated = False

    def add(self, segment: Segment, truncated: bool = False) -> None:
        flags = segment.flags
        self.fin_seen |= "F" in flags
        self.rst_seen |= "R" in flags
        self.truncated |= truncated
        if not segment.payload:
            return
        identity = (segment.sequence, segment.payload)
        if identity in self._seen:
            self.retransmissions += 1
            self.duplicates += 1
            return
        self._seen.add(identity)
        end = segment.sequence + len(segment.payload)
        if self._largest_end is not None and segment.sequence < self._largest_end:
            self.out_of_order += 1
            self.retransmissions += 1
        self._largest_end = max(self._largest_end or end, end)
        self.segments.append(segment)

    def reassemble(self) -> ReassembledStream:
        if not self.segments:
            status = "truncated" if self.truncated else ("complete" if self.fin_seen or self.rst_seen else "partial")
            return ReassembledStream(b"", status, [], self.retransmissions, self.out_of_order, self.duplicates, self.fin_seen, self.rst_seen, [])
        ordered = sorted(self.segments, key=lambda s: (s.sequence, s.frame))
        expected = ordered[0].sequence
        output = bytearray()
        missing: list[dict[str, int]] = []
        frames: list[int] = []
        for segment in ordered:
            if segment.sequence > expected:
                missing.append({"start": expected, "end": segment.sequence - 1, "length": segment.sequence - expected})
                # Deliberately stop at the first hole: appending later bytes would make
                # higher-layer parsing look complete when it is not.
                break
            overlap = max(0, expected - segment.sequence)
            if overlap < len(segment.payload):
                output.extend(segment.payload[overlap:])
                expected = segment.sequence + len(segment.payload)
                frames.append(segment.frame)
        if self.truncated:
            status = "truncated"
        elif missing:
            status = "missing_segments"
        elif self.fin_seen or self.rst_seen:
            status = "complete"
        else:
            status = "partial"
        return ReassembledStream(bytes(output), status, missing, self.retransmissions, self.out_of_order, self.duplicates, self.fin_seen, self.rst_seen, frames)


class Flow:
    def __init__(self, key: FlowKey, client: Endpoint, server: Endpoint) -> None:
        self.key, self.client, self.server = key, client, server
        self.directions = {"client_to_server": TCPDirection(), "server_to_client": TCPDirection()}
        self.packet_count = 0
        self.byte_count = 0
        self.first_timestamp: Optional[float] = None
        self.last_timestamp: Optional[float] = None
        self.frames: list[int] = []
        self.client_syn_seen = False

    def add(self, source: Endpoint, tcp: TCP, payload: bytes, frame: int, timestamp: float, truncated: bool) -> None:
        direction = "client_to_server" if source == self.client else "server_to_client"
        if direction == "client_to_server" and "S" in str(tcp.flags) and "A" not in str(tcp.flags):
            self.client_syn_seen = True
        self.packet_count += 1
        self.byte_count += len(payload)
        self.first_timestamp = timestamp if self.first_timestamp is None else min(self.first_timestamp, timestamp)
        self.last_timestamp = timestamp if self.last_timestamp is None else max(self.last_timestamp, timestamp)
        self.frames.append(frame)
        self.directions[direction].add(Segment(int(tcp.seq), payload, frame, timestamp, str(tcp.flags)), truncated)


def _u24(data: bytes) -> int:
    return int.from_bytes(data, "big")


def _take(data: bytes, offset: int, size: int) -> tuple[bytes, int]:
    if offset + size > len(data):
        raise ValueError("truncated TLS structure")
    return data[offset:offset + size], offset + size


def _vector(data: bytes, offset: int, length_bytes: int) -> tuple[bytes, int]:
    raw_length, offset = _take(data, offset, length_bytes)
    return _take(data, offset, int.from_bytes(raw_length, "big"))


def _hex_suite(value: int) -> str:
    return f"0x{value:04X}"


def _groups(raw: bytes) -> list[str]:
    return [GROUPS.get(int.from_bytes(raw[i:i + 2], "big"), f"0x{int.from_bytes(raw[i:i + 2], 'big'):04X}") for i in range(0, len(raw) - 1, 2)]


def _extensions(raw: bytes) -> dict[int, bytes]:
    result: dict[int, bytes] = {}
    offset = 0
    while offset + 4 <= len(raw):
        extension_type = int.from_bytes(raw[offset:offset + 2], "big")
        length = int.from_bytes(raw[offset + 2:offset + 4], "big")
        offset += 4
        value, offset = _take(raw, offset, length)
        result[extension_type] = value
    if offset != len(raw):
        raise ValueError("truncated TLS extension")
    return result


def _extension_summary(extensions: dict[int, bytes]) -> dict[str, Any]:
    output: dict[str, Any] = {"types": [f"0x{k:04X}" for k in sorted(extensions)]}
    if 0 in extensions and len(extensions[0]) >= 5:
        names, offset = _vector(extensions[0], 0, 2)
        value, offset = _take(names, 0, 3)
        if value[0] == 0:
            output["sni"] = value[1:].decode("ascii", errors="replace")
    if 16 in extensions:
        protocols, _ = _vector(extensions[16], 0, 2)
        values, offset = [], 0
        while offset < len(protocols):
            item, offset = _vector(protocols, offset, 1)
            values.append(item.decode("ascii", errors="replace"))
        output["alpn"] = values
    if 10 in extensions:
        raw, _ = _vector(extensions[10], 0, 2)
        output["supported_groups"] = _groups(raw)
    if 13 in extensions:
        raw, _ = _vector(extensions[13], 0, 2)
        output["signature_algorithms"] = [f"0x{int.from_bytes(raw[i:i+2], 'big'):04X}" for i in range(0, len(raw) - 1, 2)]
    if 43 in extensions:
        raw = extensions[43]
        if len(raw) == 2:
            output["selected_version"] = TLS_VERSIONS.get(int.from_bytes(raw, "big"), raw.hex())
        elif raw:
            versions, _ = _vector(raw, 0, 1)
            output["supported_versions"] = [TLS_VERSIONS.get(int.from_bytes(versions[i:i + 2], "big"), versions[i:i + 2].hex()) for i in range(0, len(versions) - 1, 2)]
    if 51 in extensions:
        raw = extensions[51]
        if len(raw) >= 2 and int.from_bytes(raw[:2], "big") == len(raw) - 2:  # ClientHello vector
            values, offset = raw[2:], 0
            groups: list[str] = []
            while offset + 4 <= len(values):
                group = int.from_bytes(values[offset:offset + 2], "big")
                share_length = int.from_bytes(values[offset + 2:offset + 4], "big")
                offset += 4 + share_length
                if offset > len(values):
                    break
                groups.append(GROUPS.get(group, f"0x{group:04X}"))
            output["key_share_groups"] = groups
        elif len(raw) >= 4:  # ServerHello key_share
            group = int.from_bytes(raw[:2], "big")
            output["key_share"] = {"group": GROUPS.get(group, f"0x{group:04X}"), "length": int.from_bytes(raw[2:4], "big")}
    if 41 in extensions:
        output["pre_shared_key"] = "present"
    return output


class TLSParser:
    """Record parser that delegates semantic details by negotiated TLS version."""

    def parse(self, client_data: bytes, server_data: bytes) -> dict[str, Any]:
        messages: list[dict[str, Any]] = []
        record_counts: dict[str, int] = defaultdict(int)
        for direction, data in (("client_to_server", client_data), ("server_to_client", server_data)):
            offset = self._find_record_start(data)
            if offset is None:
                continue
            handshake = bytearray()
            while offset + 5 <= len(data):
                content_type, version, length = data[offset], int.from_bytes(data[offset + 1:offset + 3], "big"), int.from_bytes(data[offset + 3:offset + 5], "big")
                if length > 18432 or offset + 5 + length > len(data):
                    break
                body = data[offset + 5:offset + 5 + length]
                offset += 5 + length
                record_counts[{20: "change_cipher_spec", 21: "alert", 22: "handshake", 23: "application_data"}.get(content_type, f"type_{content_type}")] += 1
                if content_type == 22:
                    handshake.extend(body)
                    while len(handshake) >= 4:
                        message_length = _u24(handshake[1:4])
                        if len(handshake) < message_length + 4:
                            break
                        messages.append({"direction": direction, "type": handshake[0], "name": HANDSHAKES.get(handshake[0], f"type_{handshake[0]}"), "body": bytes(handshake[4:4 + message_length]), "record_version": version})
                        del handshake[:4 + message_length]
        if not messages and not record_counts:
            return {"detected": False}
        server_hello = next((m for m in messages if m["type"] == 2), None)
        tls13 = bool(server_hello and self._server_hello_tls13(server_hello["body"]))
        parser: BaseTLSHandshakeParser = TLS13Parser() if tls13 else LegacyTLSParser()
        result = parser.parse(messages)
        if result["handshake_complete"]:
            result["handshake_completion_status"] = "observed"
        elif record_counts.get("application_data"):
            result["handshake_completion_status"] = "encrypted_or_unavailable"
        else:
            result["handshake_completion_status"] = "not_observed"
        result.update({"detected": True, "records": dict(sorted(record_counts.items())), "handshake_messages": [m["name"] for m in messages]})
        return result

    @staticmethod
    def _find_record_start(data: bytes) -> Optional[int]:
        for index in range(max(0, len(data) - 4)):
            if data[index] in (20, 21, 22, 23) and data[index + 1] == 3 and data[index + 2] <= 4:
                length = int.from_bytes(data[index + 3:index + 5], "big")
                if 0 < length <= 18432 and index + 5 + length <= len(data):
                    return index
        return None

    @staticmethod
    def _server_hello_tls13(body: bytes) -> bool:
        try:
            _, offset = _take(body, 0, 2)
            _, offset = _take(body, offset, 32)
            _, offset = _vector(body, offset, 1)
            _, offset = _take(body, offset, 2)
            _, offset = _take(body, offset, 1)
            extension_bytes, _ = _vector(body, offset, 2)
            return int.from_bytes(_extensions(extension_bytes).get(43, b"\x00\x00"), "big") == 0x0304
        except ValueError:
            return False


class BaseTLSHandshakeParser:
    def parse(self, messages: list[dict[str, Any]]) -> dict[str, Any]:
        client = next((m for m in messages if m["type"] == 1), None)
        server = next((m for m in messages if m["type"] == 2), None)
        certificates = [m for m in messages if m["type"] == 11]
        output: dict[str, Any] = {"client_hello": self._client_hello(client["body"]) if client else None, "server_hello": self._server_hello(server["body"]) if server else None, "alerts": [self._alert(m["body"]) for m in messages if m["type"] == 21], "certificate_der": []}
        for certificate in certificates:
            output["certificate_der"].extend(self._certificates(certificate["body"]))
        output["handshake_complete"] = any(m["type"] == 20 for m in messages)
        return output

    def _client_hello(self, body: bytes) -> dict[str, Any]:
        version, offset = _take(body, 0, 2)
        random, offset = _take(body, offset, 32)
        session_id, offset = _vector(body, offset, 1)
        suites, offset = _vector(body, offset, 2)
        compression, offset = _vector(body, offset, 1)
        extension_blob, _ = _vector(body, offset, 2) if offset < len(body) else (b"", offset)
        ext = _extension_summary(_extensions(extension_blob))
        return {"legacy_version": TLS_VERSIONS.get(int.from_bytes(version, "big"), version.hex()), "session_id": session_id.hex(), "offered_cipher_suites": [{"id": _hex_suite(int.from_bytes(suites[i:i + 2], "big")), "name": CIPHER_SUITES.get(int.from_bytes(suites[i:i + 2], "big"), "UNKNOWN") } for i in range(0, len(suites) - 1, 2)], "compression_methods": list(compression), "random": random.hex(), "extensions": ext}

    def _server_hello(self, body: bytes) -> dict[str, Any]:
        version, offset = _take(body, 0, 2)
        random, offset = _take(body, offset, 32)
        session_id, offset = _vector(body, offset, 1)
        suite, offset = _take(body, offset, 2)
        compression, offset = _take(body, offset, 1)
        extension_blob, _ = _vector(body, offset, 2) if offset < len(body) else (b"", offset)
        value = int.from_bytes(suite, "big")
        return {"legacy_version": TLS_VERSIONS.get(int.from_bytes(version, "big"), version.hex()), "random": random.hex(), "session_id": session_id.hex(), "cipher_suite": {"id": _hex_suite(value), "name": CIPHER_SUITES.get(value, "UNKNOWN")}, "compression_method": compression[0], "extensions": _extension_summary(_extensions(extension_blob))}

    def _certificates(self, body: bytes) -> list[bytes]:
        try:
            blob, offset = _vector(body, 0, 3)
            if offset != len(body):
                raise ValueError("unexpected Certificate bytes")
            output, offset = [], 0
            while offset < len(blob):
                der, offset = _vector(blob, offset, 3)
                output.append(der)
            return output
        except ValueError:
            return []

    @staticmethod
    def _alert(body: bytes) -> dict[str, int]:
        return {"level": body[0], "description": body[1]} if len(body) >= 2 else {"truncated": 1}


class LegacyTLSParser(BaseTLSHandshakeParser):
    """TLS 1.2-and-older cleartext handshake parser."""

    def parse(self, messages: list[dict[str, Any]]) -> dict[str, Any]:
        result = super().parse(messages)
        result["parser"] = "legacy_tls"
        result["negotiated_version"] = (result.get("server_hello") or {}).get("legacy_version")
        server_key_exchange = next((m for m in messages if m["type"] == 12), None)
        cipher = (result.get("server_hello") or {}).get("cipher_suite", {})
        result["key_exchange"] = _legacy_key_exchange(cipher.get("name"), server_key_exchange["body"] if server_key_exchange else None)
        return result


class TLS13Parser(BaseTLSHandshakeParser):
    """TLS 1.3 parser; encrypted post-ServerHello messages remain explicitly unknown."""

    def parse(self, messages: list[dict[str, Any]]) -> dict[str, Any]:
        result = super().parse(messages)
        result["parser"] = "tls13"
        result["negotiated_version"] = "TLS 1.3"
        server = result.get("server_hello") or {}
        key_share = server.get("extensions", {}).get("key_share", {})
        result["key_exchange"] = {"mechanism": "ECDHE", "group": key_share.get("group", "unknown"), "forward_secrecy": True}
        if not result["certificate_der"]:
            result["certificate_status"] = {"value": "encrypted_or_unavailable", "reason": "TLS 1.3 handshake encrypted; no session keys supplied"}
        return result


def _legacy_key_exchange(cipher_name: Optional[str], server_key_exchange: Optional[bytes]) -> dict[str, Any]:
    name = cipher_name or ""
    if "ECDHE" in name:
        group = "unknown"
        if server_key_exchange and len(server_key_exchange) >= 3 and server_key_exchange[0] == 3:
            group = GROUPS.get(int.from_bytes(server_key_exchange[1:3], "big"), f"0x{int.from_bytes(server_key_exchange[1:3], 'big'):04X}")
        return {"mechanism": "ECDHE", "group": group, "forward_secrecy": True}
    if "DHE" in name:
        return {"mechanism": "DHE", "group": "unknown", "forward_secrecy": True}
    if "RSA" in name:
        return {"mechanism": "RSA", "group": None, "forward_secrecy": False}
    return {"mechanism": "unknown", "group": None, "forward_secrecy": "unknown"}


def parse_certificate(der: bytes) -> dict[str, Any]:
    """Parse a certificate's actual ASN.1 DER bytes using cryptography/OpenSSL bindings."""
    certificate = x509.load_der_x509_certificate(der)
    public_key = certificate.public_key()
    key_size = getattr(public_key, "key_size", None)
    def extension(oid: Any) -> Any:
        try:
            return certificate.extensions.get_extension_for_oid(oid).value
        except x509.ExtensionNotFound:
            return None
    san = extension(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
    constraints = extension(ExtensionOID.BASIC_CONSTRAINTS)
    usage = extension(ExtensionOID.KEY_USAGE)
    eku = extension(ExtensionOID.EXTENDED_KEY_USAGE)
    return {"version": certificate.version.name, "serial_number": format(certificate.serial_number, "X"), "subject": certificate.subject.rfc4514_string(), "issuer": certificate.issuer.rfc4514_string(), "not_before": certificate.not_valid_before_utc.isoformat(), "not_after": certificate.not_valid_after_utc.isoformat(), "signature_algorithm": certificate.signature_algorithm_oid.dotted_string, "public_key_algorithm": public_key.__class__.__name__, "public_key_size": key_size, "san": _san_values(san), "basic_constraints": {"ca": constraints.ca, "path_length": constraints.path_length} if constraints else None, "key_usage": _key_usage(usage), "extended_key_usage": [oid.dotted_string for oid in eku] if eku else [], "fingerprint_sha256": certificate.fingerprint(hashes.SHA256()).hex(), "ca_status": constraints.ca if constraints else False, "_certificate": certificate}


def _san_values(san: Any) -> list[str]:
    if san is None:
        return []
    values: list[str] = []
    for name in san:
        if isinstance(name, x509.DNSName):
            values.append(f"DNS:{name.value}")
        elif isinstance(name, x509.IPAddress):
            values.append(f"IP:{name.value}")
        elif isinstance(name, x509.RFC822Name):
            values.append(f"email:{name.value}")
        elif isinstance(name, x509.UniformResourceIdentifier):
            values.append(f"URI:{name.value}")
        else:
            values.append(str(name))
    return values


def _key_usage(usage: Any) -> Optional[list[str]]:
    if usage is None:
        return None
    names = ("digital_signature", "content_commitment", "key_encipherment", "data_encipherment", "key_agreement", "key_cert_sign", "crl_sign")
    return [name for name in names if getattr(usage, name)]


def validate_chain(certificates: list[dict[str, Any]], now: Optional[datetime] = None) -> list[dict[str, Any]]:
    now = now or datetime.now(timezone.utc)
    for index, item in enumerate(certificates):
        certificate = item.pop("_certificate")
        item["validation"] = {"expired": now > certificate.not_valid_after_utc, "not_yet_valid": now < certificate.not_valid_before_utc, "self_signed": certificate.subject == certificate.issuer, "observed_chain_complete": False, "issuer_relationship_verified": False, "local_trust_evaluated": False}
        if index + 1 < len(certificates):
            issuer = certificates[index + 1]["_certificate"]
            item["validation"]["issuer_relationship_verified"] = certificate.issuer == issuer.subject and _verify_signature(certificate, issuer)
            item["validation"]["observed_chain_complete"] = item["validation"]["issuer_relationship_verified"]
        elif item["validation"]["self_signed"]:
            item["validation"]["issuer_relationship_verified"] = _verify_signature(certificate, certificate)
            item["validation"]["observed_chain_complete"] = item["validation"]["issuer_relationship_verified"]
    for item in certificates:
        item.pop("_certificate", None)
    return certificates


def _verify_signature(child: x509.Certificate, issuer: x509.Certificate) -> bool:
    try:
        key = issuer.public_key()
        if isinstance(key, rsa.RSAPublicKey):
            key.verify(child.signature, child.tbs_certificate_bytes, padding.PKCS1v15(), child.signature_hash_algorithm)
        elif isinstance(key, ec.EllipticCurvePublicKey):
            key.verify(child.signature, child.tbs_certificate_bytes, ec.ECDSA(child.signature_hash_algorithm))
        elif isinstance(key, dsa.DSAPublicKey):
            key.verify(child.signature, child.tbs_certificate_bytes, child.signature_hash_algorithm)
        else:
            key.verify(child.signature, child.tbs_certificate_bytes)
        return True
    except Exception:  # malformed or unsupported signature algorithms are forensic facts, not fatal errors
        return False


def identify_email_protocol(client: bytes, server: bytes, frames: list[int]) -> Evidence:
    text = (client + b"\n" + server).upper()
    markers = {"SMTP": [b"EHLO", b"HELO", b"MAIL FROM", b"RCPT TO", b"STARTTLS"], "IMAP": [b" CAPABILITY", b" STARTTLS", b" LOGIN", b"* OK"], "POP3": [b"+OK", b"CAPA", b"STLS", b"USER ", b"PASS "]}
    scores = {name: sum(marker in text for marker in values) for name, values in markers.items()}
    protocol, score = max(scores.items(), key=lambda item: item[1])
    if not score:
        return Evidence("unknown", "low", ["No email protocol indicators observed"], frames[:3])
    confidence = "high" if score >= 2 else "medium"
    found = [marker.decode("ascii") for marker in markers[protocol] if marker in text]
    return Evidence(protocol, confidence, [f"{protocol} indicator observed: {item}" for item in found], frames[:8])


def encryption_mode(protocol: str, client: bytes, server: bytes, tls_detected: bool, frames: list[int]) -> Evidence:
    upper = (client + b"\n" + server).upper()
    upgrade = {"SMTP": b"STARTTLS", "IMAP": b" STARTTLS", "POP3": b"STLS"}.get(protocol)
    if upgrade and upgrade in upper and tls_detected:
        return Evidence("STARTTLS", "high", [f"{protocol} upgrade command observed", "TLS record follows in reconstructed stream"], frames[:8])
    if tls_detected:
        return Evidence("implicit_tls", "medium", ["TLS records observed without a plaintext upgrade command"], frames[:8])
    if protocol != "unknown":
        return Evidence("none", "high", ["Plaintext email protocol observed; no TLS records found"], frames[:8])
    return Evidence("unknown", "low", ["No conclusive protocol/encryption evidence"], frames[:8])


def _iso(timestamp: Optional[float]) -> Optional[str]:
    return datetime.fromtimestamp(timestamp, timezone.utc).isoformat() if timestamp is not None else None


def _stream_json(stream: ReassembledStream) -> dict[str, Any]:
    """Expose reassembly facts, never raw application bytes, in the stable schema."""
    result = asdict(stream)
    result.pop("data")
    result["reassembled_bytes"] = len(stream.data)
    return result


class ForensicParser:
    """Stateful per-file parser; reader iteration keeps packet acquisition streaming."""

    def parse_file(self, path: str | Path) -> dict[str, Any]:
        path = Path(path)
        flows: dict[FlowKey, Flow] = {}
        packet_total = tcp_total = 0
        timestamps: list[float] = []
        with PcapReader(str(path)) as reader:
            for frame, packet in enumerate(reader, 1):
                packet_total += 1
                timestamp = float(packet.time)
                timestamps.append(timestamp)
                if not packet.haslayer(TCP) or not (packet.haslayer(IP) or packet.haslayer(IPv6)):
                    continue
                network = packet[IP] if packet.haslayer(IP) else packet[IPv6]
                tcp = packet[TCP]
                source, destination = Endpoint(str(network.src), int(tcp.sport)), Endpoint(str(network.dst), int(tcp.dport))
                key = FlowKey.canonical(source, destination)
                flow = flows.get(key)
                if flow is None:
                    # SYN source is authoritative. For mid-capture traffic, the first
                    # observed source is retained and marked partial by reassembly.
                    client, server = (source, destination) if "S" in str(tcp.flags) and "A" not in str(tcp.flags) else (source, destination)
                    flow = flows[key] = Flow(key, client, server)
                payload = bytes(tcp.payload)
                truncated = bool(getattr(packet, "wirelen", len(bytes(packet))) > len(bytes(packet)))
                flow.add(source, tcp, payload, frame, timestamp, truncated)
                tcp_total += 1
        sessions = [self._session(flow, index + 1) for index, flow in enumerate(sorted(flows.values(), key=lambda item: (item.first_timestamp or 0, item.key.left, item.key.right)))]
        return {"schema_version": SCHEMA_VERSION, "pcap": {"path": str(path), "sha256": _sha256(path), "packet_count": packet_total, "tcp_packet_count": tcp_total, "first_timestamp": _iso(min(timestamps)) if timestamps else None, "last_timestamp": _iso(max(timestamps)) if timestamps else None}, "sessions": sessions}

    def _session(self, flow: Flow, number: int) -> dict[str, Any]:
        c2s, s2c = flow.directions["client_to_server"].reassemble(), flow.directions["server_to_client"].reassemble()
        warnings: list[str] = []
        for name, stream in (("client_to_server", c2s), ("server_to_client", s2c)):
            if stream.status != "complete":
                warnings.append(f"{name} reassembly is {stream.status}")
        protocol = identify_email_protocol(c2s.data, s2c.data, flow.frames)
        try:
            tls = TLSParser().parse(c2s.data, s2c.data)
        except Exception as error:
            # A malformed TLS flow is isolated: forensic analysis continues for all
            # other sessions in the same capture.
            tls = {"detected": False, "parse_error": str(error)}
            warnings.append(f"TLS parse failed: {error}")
        encryption = encryption_mode(protocol.value, c2s.data, s2c.data, tls.get("detected", False), flow.frames)
        certificates: list[dict[str, Any]] = []
        for der in tls.pop("certificate_der", []):
            try:
                certificates.append(parse_certificate(der))
            except Exception as error:
                warnings.append(f"X.509 certificate parse failed: {error}")
        if certificates:
            validate_chain(certificates)
            cert_evidence = Evidence("available", "high", [f"{len(certificates)} DER certificate(s) observed in TLS Certificate handshake"], flow.frames[:8])
        elif tls.get("parser") == "tls13":
            cert_evidence = Evidence("encrypted_or_unavailable", "high", ["TLS 1.3 post-ServerHello certificate data is encrypted without session keys"], flow.frames[:8])
        else:
            cert_evidence = Evidence("unavailable", "medium", ["No observable TLS Certificate handshake"], flow.frames[:8])
        negotiated = tls.get("server_hello", {}).get("cipher_suite") if tls.get("server_hello") else None
        evidence = [asdict(protocol), asdict(encryption), asdict(cert_evidence)]
        if tls.get("detected"):
            evidence.append(asdict(Evidence(tls.get("negotiated_version", "unknown"), "high" if tls.get("server_hello") else "medium", ["ServerHello parsed from reconstructed TCP stream"], flow.frames[:8])))
        if negotiated:
            evidence.append(asdict(Evidence(negotiated["name"], "high", [f"ServerHello selected {negotiated['id']}"], flow.frames[:8])))
        statuses = [c2s.status, s2c.status]
        session_reassembly = "complete" if flow.client_syn_seen and statuses == ["complete", "complete"] else "partial"
        if not flow.client_syn_seen:
            warnings.append("Client SYN was not observed; capture may begin mid-session")
        parse_status = "error" if not flow.packet_count else session_reassembly
        return {"session_id": f"tcp-{number:04d}", "parse_status": parse_status, "network": {"protocol": "TCP", "client": asdict(flow.client), "server": asdict(flow.server), "first_timestamp": _iso(flow.first_timestamp), "last_timestamp": _iso(flow.last_timestamp), "packet_frames": flow.frames}, "tcp": {"packet_count": flow.packet_count, "payload_bytes": flow.byte_count, "reassembly_status": session_reassembly, "client_syn_seen": flow.client_syn_seen, "fin_seen": c2s.fin_seen or s2c.fin_seen, "rst_seen": c2s.rst_seen or s2c.rst_seen, "client_to_server": _stream_json(c2s), "server_to_client": _stream_json(s2c)}, "email_protocol": asdict(protocol), "encryption": asdict(encryption), "tls": tls, "certificates": certificates, "certificate_availability": asdict(cert_evidence), "evidence": evidence, "warnings": warnings}


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def main(argv: Optional[list[str]] = None) -> int:
    argument_parser = argparse.ArgumentParser(description=__doc__)
    argument_parser.add_argument("pcap", type=Path)
    argument_parser.add_argument("--output", type=Path, help="Write JSON result to this path")
    argument_parser.add_argument("--session", help="Emit only this session id")
    argument_parser.add_argument("--verbose", action="store_true")
    args = argument_parser.parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.WARNING, format="%(levelname)s %(message)s")
    try:
        result = ForensicParser().parse_file(args.pcap)
    except (OSError, ValueError) as error:
        argument_parser.error(str(error))
    if args.session:
        result["sessions"] = [session for session in result["sessions"] if session["session_id"] == args.session]
    rendered = json.dumps(result, indent=2, sort_keys=True)
    if args.output:
        args.output.write_text(rendered + "\n", encoding="utf-8")
    else:
        print(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
