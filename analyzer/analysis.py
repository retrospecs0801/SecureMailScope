"""Pure deterministic cryptographic risk analysis for one parser session."""

from __future__ import annotations

from analyzer.confidence import compute_session_confidence


RISK_VALUES = {"low": 25, "moderate": 50, "high": 75, "critical": 100}
RISK_LABELS = {value: label for label, value in RISK_VALUES.items()}
OPPORTUNISTIC_PORTS = {25, 110, 143, 587}
IMPLICIT_TLS_PORTS = {465, 993, 995}

OID_NAMES = {
    "1.2.840.113549.1.1.4": "md5WithRSAEncryption",
    "1.2.840.113549.1.1.5": "sha1WithRSAEncryption",
    "1.2.840.113549.1.1.11": "sha256WithRSAEncryption",
    "1.2.840.113549.1.1.12": "sha384WithRSAEncryption",
    "1.2.840.113549.1.1.13": "sha512WithRSAEncryption",
    "1.2.840.10045.4.3.2": "ecdsa-with-SHA256",
    "1.2.840.10045.4.3.3": "ecdsa-with-SHA384",
    "1.2.840.10045.4.3.4": "ecdsa-with-SHA512",
}


def _finding(check: str, observed: object, risk: str, reference: str, rationale: str, confidence: str, contributes_to_score: bool = True) -> dict:
    return {
        "check": check,
        "observed_value": str(observed),
        "risk_level": risk,
        "reference": reference,
        "rationale": rationale,
        "confidence": confidence,
        "contributes_to_score": bool(contributes_to_score),
    }


def _unavailable(check: str, observed: object, rationale: str, confidence: str) -> dict:
    return _finding(check, observed, "low", "N/A", rationale, confidence)


def _tls_findings(session: dict, confidence: str) -> list[dict]:
    tls = session.get("tls", {})
    version = tls.get("negotiated_version", "unknown")
    if version in {"TLS 1.0", "TLS 1.1", "SSL 3.0", "SSL 2.0"}:
        risk, rationale = "critical", f"{version} is deprecated and unsafe for modern use per RFC 8996."
    elif version == "TLS 1.2":
        risk, rationale = "moderate", "TLS 1.2 remains acceptable as a baseline; cipher and key exchange checks provide the specific verdict."
    elif version == "TLS 1.3":
        risk, rationale = "low", "TLS 1.3 is the current preferred TLS version."
    else:
        result = [_unavailable("tls_version", version, "TLS version could not be positively identified.", confidence)]
    if version in {"TLS 1.0", "TLS 1.1", "SSL 3.0", "SSL 2.0", "TLS 1.2", "TLS 1.3"}:
        result = [_finding("tls_version", version, risk, "RFC 8996", rationale, confidence)]

    cipher = tls.get("server_hello", {}).get("cipher_suite", {})
    cipher_name = cipher.get("name", "UNKNOWN")
    cipher_id = cipher.get("id", "unknown")
    upper = str(cipher_name).upper()
    if cipher_name == "UNKNOWN" or not upper:
        result.append(_unavailable("cipher_suite", cipher_name, f"Cipher suite is unmapped; raw cipher ID is {cipher_id}.", confidence))
    elif any(token in upper for token in ("RC4", "3DES", "NULL", "EXPORT", "ANON", "DES")):
        result.append(_finding("cipher_suite", cipher_name, "critical", "RFC 9325", f"Cipher suite {cipher_name} uses a prohibited or obsolete construction.", confidence))
    elif "CBC" in upper and not any(token in upper for token in ("GCM", "POLY1305", "CCM")):
        result.append(_finding("cipher_suite", cipher_name, "high", "RFC 9325", f"Cipher suite {cipher_name} uses CBC without an AEAD mode.", confidence))
    elif any(token in upper for token in ("GCM", "POLY1305", "CCM")):
        mechanism = str(tls.get("key_exchange", {}).get("mechanism", "unknown")).upper()
        if "ECDHE" in mechanism or "DHE" in mechanism:
            result.append(_finding("cipher_suite", cipher_name, "low", "RFC 9325", f"Cipher suite {cipher_name} provides AEAD encryption with ephemeral key exchange.", confidence))
        elif "RSA" in upper and "ECDHE" not in upper and "DHE" not in upper:
            result.append(_finding("cipher_suite", cipher_name, "high", "RFC 9325", f"Cipher suite {cipher_name} uses static RSA and does not provide forward secrecy.", confidence))
        else:
            result.append(_unavailable("cipher_suite", cipher_name, f"Cipher suite {cipher_name} is not mapped for this key-exchange combination; raw cipher ID is {cipher_id}.", confidence))
    else:
        result.append(_unavailable("cipher_suite", cipher_name, f"Cipher suite {cipher_name} is unmapped; raw cipher ID is {cipher_id}.", confidence))

    key_exchange = tls.get("key_exchange", {})
    forward_secrecy = key_exchange.get("forward_secrecy", "unknown")
    mechanism = key_exchange.get("mechanism", "unknown")
    if forward_secrecy is True:
        result.append(_finding("key_exchange", mechanism, "low", "RFC 9325", f"Key exchange {mechanism} provides forward secrecy.", confidence))
    elif forward_secrecy is False:
        result.append(_finding("key_exchange", mechanism, "high", "RFC 9325", f"Key exchange {mechanism} does not provide forward secrecy.", confidence))
    else:
        result.append(_unavailable("key_exchange", mechanism, "Forward secrecy status is unknown.", confidence))
    return result


def _certificate_findings(session: dict, confidence: str, warnings: list[str]) -> list[dict]:
    if session.get("certificate_availability", {}).get("value") != "available":
        return []
    certificates = session.get("certificates", [])
    result: list[dict] = []
    for index, certificate in enumerate(certificates):
        validation = certificate.get("validation", {})
        constraints = certificate.get("basic_constraints", {})
        validity_check = f"certificate_validity[{index}]"
        if validation.get("expired") is True:
            result.append(_finding(validity_check, certificate.get("not_after", "unknown"), "critical", "RFC 5280", f"Certificate {index} is expired; its not_after value is {certificate.get('not_after', 'unknown')}.", confidence))
        elif validation.get("not_yet_valid") is True:
            result.append(_finding(validity_check, certificate.get("not_before", "unknown"), "high", "RFC 5280", f"Certificate {index} is not yet valid; its not_before value is {certificate.get('not_before', 'unknown')}.", confidence))
        elif validation.get("self_signed") is True and constraints.get("ca") is False:
            result.append(_finding(validity_check, "self-signed leaf", "critical", "RFC 5280", f"Certificate {index} is a self-signed leaf and has no real PKI trust.", confidence))
        elif validation.get("self_signed") is True and constraints.get("ca") is True:
            result.append(_finding(validity_check, "self-signed root CA", "low", "RFC 5280", "Self-signed root CA - trust depends on the local trust store, not itself a finding against the leaf.", confidence))
        else:
            result.append(_finding(validity_check, "validity checks passed", "low", "RFC 5280", f"Certificate {index} has no observed expiry, validity-window, or disallowed self-signing issue.", confidence))

        chain = validation.get("observed_chain_complete")
        issuer_verified = validation.get("issuer_relationship_verified")
        if index == 0:
            if chain is False:
                chain_risk, chain_text = "high", "the observed certificate chain is incomplete and its path cannot be verified"
            elif chain is True and issuer_verified is False:
                chain_risk, chain_text = "moderate", "the chain is present but the issuer relationship could not be verified"
            elif chain is True and issuer_verified is True:
                chain_risk, chain_text = "low", "the observed chain is complete and issuer relationships are verified"
            else:
                chain_risk, chain_text = "low", "chain completeness information is unavailable"
            result.append(_finding("certificate_chain", chain if chain is not None else "unknown", chain_risk, "RFC 5280", f"{chain_text}; validation.local_trust_evaluated is expected to be false for this passive analyzer and is not itself a finding.", confidence))

        algorithm = str(certificate.get("public_key_algorithm", "")).upper()
        size = certificate.get("public_key_size")
        strength_check = f"public_key_strength[{index}]"
        if "RSA" in algorithm and isinstance(size, int):
            strength_risk = "critical" if size < 2048 else "low"
            result.append(_finding(strength_check, f"{certificate.get('public_key_algorithm')} {size}", strength_risk, "NIST SP 800-131A Rev 2", f"RSA public key size is {size} bits.", confidence))
        elif ("EC" in algorithm or "ECDSA" in algorithm) and isinstance(size, int):
            strength_risk = "critical" if size < 224 else "low"
            result.append(_finding(strength_check, f"{certificate.get('public_key_algorithm')} {size}", strength_risk, "NIST SP 800-131A Rev 2", f"Elliptic-curve public key size is {size} bits.", confidence))
        else:
            result.append(_unavailable(strength_check, certificate.get("public_key_algorithm", "unknown"), f"Public-key algorithm {certificate.get('public_key_algorithm', 'unknown')} is unmapped.", confidence))

        oid = str(certificate.get("signature_algorithm", "unknown"))
        name = OID_NAMES.get(oid)
        signature_check = f"signature_algorithm[{index}]"
        if name == "md5WithRSAEncryption":
            signature_risk = "critical"
        elif name == "sha1WithRSAEncryption" or "sha1" in name.lower() if name else False:
            signature_risk = "high"
        elif name:
            signature_risk = "low"
        else:
            warnings.append(f"unresolved certificate signature OID: {oid}")
            result.append(_unavailable(signature_check, oid, f"Certificate signature OID {oid} is not mapped.", confidence))
            continue
        result.append(_finding(signature_check, f"{oid} ({name})", signature_risk, "RFC 5280", f"Certificate signature algorithm is {name}.", confidence))
    return result


def _encryption_finding(session: dict, confidence: str) -> dict:
    encryption = session.get("encryption", {}).get("value", "unknown")
    port = session.get("network", {}).get("server", {}).get("port")
    if encryption == "STARTTLS" and port in OPPORTUNISTIC_PORTS:
        risk, rationale = "low", f"STARTTLS is used on opportunistic mail port {port}, which is expected."
        contributes = True
    elif encryption == "none" and port in OPPORTUNISTIC_PORTS:
        risk, rationale = "high", f"STARTTLS was not used on opportunistic port {port}; a plaintext session was observed (RFC 3207 / RFC 8314)."
        contributes = True
    elif encryption == "none" and port in IMPLICIT_TLS_PORTS:
        risk, rationale = "critical", f"Plaintext protocol was observed on implicit-TLS port {port}, indicating an implicit-TLS bypass (RFC 8314)."
        contributes = True
    elif encryption == "implicit_tls" and port in IMPLICIT_TLS_PORTS:
        risk, rationale = "low", f"Implicit TLS is used on implicit-TLS port {port}, which is expected."
        contributes = True
    elif port not in OPPORTUNISTIC_PORTS | IMPLICIT_TLS_PORTS:
        risk, rationale = "moderate", f"Encryption mode {encryption} was observed on nonstandard mail port {port}; the port mapping is ambiguous."
        contributes = False
    else:
        risk, rationale = "moderate", f"Encryption mode {encryption} does not match the expected behavior for server port {port}."
        contributes = True
    return _finding("encryption_transition", f"{encryption} on port {port}", risk, "RFC 3207 / RFC 8314", rationale, confidence, contributes)


def analyze_session(session: dict) -> dict:
    """Analyze one schema 1.0 parser session without I/O or nondeterminism."""
    confidence_result = compute_session_confidence(session)
    confidence = confidence_result["level"]
    warnings = list(session.get("warnings", []))
    findings = _tls_findings(session, confidence)
    findings.extend(_certificate_findings(session, confidence, warnings))
    findings.append(_encryption_finding(session, confidence))

    scorable = [
        finding for finding in findings
        if finding.get("risk_level") in RISK_VALUES
        and finding.get("risk_level") != "data_unavailable"
        and bool(finding.get("contributes_to_score", True))
    ]
    score = max((RISK_VALUES[finding["risk_level"]] for finding in scorable), default=0)
    independent_high = {
        finding["check"].split("[", 1)[0]
        for finding in scorable
        if RISK_VALUES[finding["risk_level"]] >= 75
    }
    if len(independent_high) >= 3:
        score = min(100, score + 25)
    if not scorable:
        warnings.append("no scorable findings - insufficient evidence")
    return {
        "session_id": session.get("session_id", "unknown"),
        "confidence": confidence_result,
        "findings": findings,
        "deterministic_score": score,
        "deterministic_risk": RISK_LABELS.get(score, "low"),
        "warnings": warnings,
    }