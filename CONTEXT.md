# SecureMailScope — Antigravity Context / Handoff

## 1. Project Purpose

SecureMailScope is an AI-assisted passive network forensic framework for analyzing PCAPs containing email traffic, primarily SMTP, IMAP, and POP3.

The intended pipeline is:

```text
PCAP
  ↓
Packet Reader
  ↓
TCP Flow Tracking / Reassembly
  ↓
Email Protocol Detection
  ↓
STARTTLS / Implicit TLS Detection
  ↓
TLS Version-Specific Parsing
  ├── Legacy TLS ≤ 1.2
  └── TLS 1.3
  ↓
X.509 Certificate Extraction / Validation
  ↓
Structured Forensic JSON
  ↓
risk_analysis.py
  ↓
recommendation.py
  ↓
JSON / PDF / HTML / Dashboard
```

The parser is deliberately a deterministic forensic layer. Risk scoring, AI/ML decisions, recommendations, reporting, and dashboards are separate layers.

---

## 2. Current Project State

### Verified and working

- Postfix-based Docker test infrastructure works on Windows.
- SMTP STARTTLS with TLS 1.2 has been successfully negotiated.
- A real CA-signed certificate chain is used.
- A real PCAP has been captured with tshark.
- The passive parser has been implemented and tested.
- The parser successfully analyzes the current TLS 1.2 SMTP fixture.
- Unit/integration test suite reported 9 passing tests.

### Current baseline fixture

The known-good baseline is:

- Email protocol: SMTP
- Encryption mode: STARTTLS
- TLS version: TLS 1.2
- Cipher: `0xC030` / `ECDHE-RSA-AES256-GCM-SHA384`
- Key exchange: ECDHE
- Group: x25519
- Forward secrecy: true
- Certificates observed: 2
- Leaf certificate:
  - Subject: `CN=mail.securemailscope.local,O=SecureMailScope,C=US`
  - Public key: RSA 2048
  - SANs:
    - `mail.securemailscope.local`
    - `localhost`
- Root CA: RSA 4096, self-signed

The current PCAP contains 50 packets and 50 TCP packets.

---

## 3. Docker / Postfix Test Infrastructure

### Files

```text
Dockerfile
docker-compose.yml
.gitignore
.dockerignore

postfix/
  tls-config.sh

scripts/
  generate_certs.sh
  send_test_email.py

certs/
  .gitkeep
  <generated CA/server PKI>

capture/
  postfix_tls12.pcapng
```

`postfix/main.cf` was intentionally removed. Postfix configuration is applied through the container startup/configuration mechanism rather than a read-only bind-mounted `main.cf`.

### Current server

- Container: `securemailscope-postfix`
- SMTP mapping: `localhost:2525 → container:25`
- Postfix: 3.10.5
- OpenSSL: 3.5.4
- SMTP delivery test succeeds.
- Test mail is delivered through the local discard transport; the queue is empty.

### Certificate baseline

Root CA:

- RSA 4096-bit
- Self-signed
- Long-lived test CA

Server certificate:

- RSA 2048-bit
- CA-signed
- Subject: `CN=mail.securemailscope.local,O=SecureMailScope,C=US`
- Issuer: `CN=SecureMailScope Test Root CA,O=SecureMailScope Test PKI,C=US`
- SANs:
  - `DNS:mail.securemailscope.local`
  - `DNS:localhost`

OpenSSL verification passed for the baseline.

### Baseline commands

```powershell
docker compose build
docker compose --profile tools run --rm certgen
docker compose up -d postfix
python scripts/send_test_email.py
```

Force fresh certificates:

```powershell
$env:FORCE_REGENERATE='1'; docker compose --profile tools run --rm certgen
```

Verify TLS:

```powershell
@('QUIT') | & 'C:\Program Files\OpenSSL-Win64\bin\openssl.exe' s_client -starttls smtp -connect localhost:2525 -servername localhost -tls1_2 -cipher ECDHE-RSA-AES256-GCM-SHA384 -CAfile certs/ca.crt -verify_return_error -brief
```

Inspect the baseline PCAP:

```powershell
tshark -r capture\postfix_tls12.pcapng -d tcp.port==2525,smtp -Y tls.handshake -T fields -e tls.handshake.type -e tls.handshake.version -e tls.handshake.ciphersuite
```

---

# 4. Parser Architecture

Primary parser:

```text
analyzer/parser.py
```

Supporting:

```text
analyzer/__init__.py
tests/test_parser.py
requirements.txt
```

The parser is implemented as a passive forensic parser with these major components:

1. PCAP/PCAPNG packet reading using Scapy.
2. Canonical bidirectional TCP flow tracking.
3. Per-direction sequence-aware TCP reassembly.
4. Duplicate/retransmission handling.
5. Out-of-order handling.
6. FIN/RST tracking.
7. Missing-range detection.
8. Partial/truncated-session status reporting.
9. Evidence-based SMTP/IMAP/POP3 identification.
10. STARTTLS detection.
11. Implicit-TLS detection.
12. TLS record/handshake reconstruction across TCP segmentation.
13. Separate legacy TLS parser and TLS 1.3 parser.
14. TLS 1.2 version/cipher/key-exchange extraction.
15. TLS 1.3 encrypted-certificate availability handling.
16. DER X.509 parsing.
17. Certificate chain relationship checks.
18. Certificate fingerprints.
19. SAN extraction.
20. Certificate constraints/usages.
21. Certificate validity timestamps.
22. Structured evidence and confidence.
23. Stable versioned JSON output.

---

# 5. Parser Contract — Actual JSON Schema Shape

The following is based on the real parser output from the verified TLS 1.2 fixture.

Top-level object:

```json
{
  "pcap": {
    "first_timestamp": "...",
    "last_timestamp": "...",
    "packet_count": 50,
    "path": "capture\\postfix_tls12.pcapng",
    "sha256": "...",
    "tcp_packet_count": 50
  },
  "schema_version": "1.0",
  "sessions": []
}
```

## 5.1 `pcap`

Fields observed:

```text
pcap.first_timestamp
pcap.last_timestamp
pcap.packet_count
pcap.path
pcap.sha256
pcap.tcp_packet_count
```

These describe the input capture itself.

Do not remove the SHA-256 field: it is useful for forensic integrity and reproducibility.

---

# 6. Session Object Schema

Each TCP/email session is represented under:

```text
sessions[]
```

Known session-level fields include:

```text
session_id
parse_status
network
tcp
email_protocol
encryption
tls
certificates
certificate_availability
evidence
warnings
```

A representative verified session:

```json
{
  "session_id": "tcp-0001",
  "parse_status": "complete",
  "network": {},
  "tcp": {},
  "email_protocol": {},
  "encryption": {},
  "tls": {},
  "certificates": [],
  "certificate_availability": {},
  "evidence": [],
  "warnings": []
}
```

---

# 7. Evidence Object Contract

The parser repeatedly uses this structure:

```json
{
  "confidence": "high",
  "evidence": [
    "human-readable forensic evidence"
  ],
  "frames": [1, 2, 3],
  "value": "..."
}
```

Examples from the real fixture:

```text
email_protocol:
  confidence: high
  evidence:
    - SMTP indicator observed: EHLO
    - SMTP indicator observed: STARTTLS
  value: SMTP
```

```text
encryption:
  confidence: high
  evidence:
    - SMTP upgrade command observed
    - TLS record follows in reconstructed stream
  value: STARTTLS
```

```text
TLS version evidence:
  confidence: high
  evidence:
    - ServerHello parsed from reconstructed TCP stream
  value: TLS 1.2
```

```text
Cipher evidence:
  confidence: high
  evidence:
    - ServerHello selected 0xC030
  value: ECDHE-RSA-AES256-GCM-SHA384
```

Treat `confidence`, `evidence`, and `frames` as first-class forensic provenance fields.

---

# 8. Network Schema

Observed structure:

```json
{
  "network": {
    "client": {
      "address": "::1",
      "port": 58799
    },
    "first_timestamp": "...",
    "last_timestamp": "...",
    "packet_frames": [1, 2, 3],
    "protocol": "TCP",
    "server": {
      "address": "::1",
      "port": 2525
    }
  }
}
```

Fields:

```text
network.client.address
network.client.port

network.server.address
network.server.port

network.protocol
network.first_timestamp
network.last_timestamp
network.packet_frames
```

`packet_frames` provides the packet/frame provenance for the session.

---

# 9. TCP Reassembly Schema

Observed structure:

```json
{
  "tcp": {
    "client_syn_seen": true,
    "client_to_server": {
      "duplicate_segments": 0,
      "fin_seen": false,
      "frames": [],
      "missing_ranges": [],
      "out_of_order": 0,
      "reassembled_bytes": 855,
      "retransmissions": 0,
      "rst_seen": true,
      "status": "complete"
    },
    "fin_seen": true,
    "packet_count": 50,
    "payload_bytes": 4935,
    "reassembly_status": "complete",
    "rst_seen": true,
    "server_to_client": {
      "duplicate_segments": 0,
      "fin_seen": true,
      "frames": [],
      "missing_ranges": [],
      "out_of_order": 0,
      "reassembled_bytes": 4080,
      "retransmissions": 0,
      "rst_seen": false,
      "status": "complete"
    }
  }
}
```

Important semantics:

- `reassembled_bytes` is per direction.
- `missing_ranges` must never be silently ignored.
- `status` expresses whether that direction is complete.
- `reassembly_status` expresses the session-level reassembly result.
- Retransmissions, duplicates, and out-of-order packets are tracked separately.
- A packet capture may contain RST and still have `reassembly_status: complete` when all application bytes required for parsing are present. Do not equate `RST` with automatic parse failure.
- The parser must not fabricate contiguous data across a missing sequence range.
- Current prototype does not need multi-gigabyte PCAP optimization; correctness of reassembly is the priority.

---

# 10. Email Protocol Schema

Observed:

```json
{
  "email_protocol": {
    "confidence": "high",
    "evidence": [
      "SMTP indicator observed: EHLO",
      "SMTP indicator observed: STARTTLS"
    ],
    "frames": [1, 2, 3],
    "value": "SMTP"
  }
}
```

Expected protocol values:

```text
SMTP
IMAP
POP3
unknown / unavailable
```

Protocol identification must be evidence-based, not port-only.

Known upgrade commands:

```text
SMTP: STARTTLS
IMAP: STARTTLS
POP3: STLS
```

---

# 11. Encryption Schema

Observed:

```json
{
  "encryption": {
    "confidence": "high",
    "evidence": [
      "SMTP upgrade command observed",
      "TLS record follows in reconstructed stream"
    ],
    "frames": [1, 2, 3],
    "value": "STARTTLS"
  }
}
```

Important classification:

```text
STARTTLS
implicit TLS
plaintext
unknown
```

Implicit TLS is a genuinely direct TLS session where TLS begins without an application-layer STARTTLS/STLS upgrade command.

Do not classify implicit TLS merely because a well-known implicit-TLS port is used. Use protocol/TLS evidence.

---

# 12. TLS Schema

Observed top-level TLS structure:

```json
{
  "tls": {
    "alerts": [],
    "client_hello": {},
    "detected": true,
    "handshake_complete": false,
    "handshake_completion_status": "encrypted_or_unavailable",
    "handshake_messages": [],
    "key_exchange": {},
    "negotiated_version": "TLS 1.2",
    "parser": "legacy_tls",
    "records": {},
    "server_hello": {}
  }
}
```

## 12.1 TLS metadata

```text
tls.detected
tls.negotiated_version
tls.parser
tls.handshake_complete
tls.handshake_completion_status
tls.handshake_messages[]
tls.alerts[]
```

Possible parser identifiers:

```text
legacy_tls
tls13
```

The exact allowed future values should remain version-specific and stable.

---

# 13. TLS Record Counts

Observed:

```json
"records": {
  "alert": 1,
  "application_data": 12,
  "change_cipher_spec": 2,
  "handshake": 9
}
```

These are reconstructed TLS record counts by content type.

Do not confuse TLS 1.3 encrypted application/handshake records with plaintext application-level messages.

---

# 14. TLS 1.2 ClientHello Schema

Observed fields:

```json
{
  "client_hello": {
    "compression_methods": [0],
    "extensions": {
      "signature_algorithms": [
        "0x0403",
        "0x0503"
      ],
      "sni": "...",
      "supported_groups": [
        "x25519",
        "secp256r1",
        "x448",
        "secp521r1",
        "secp384r1"
      ],
      "types": [
        "0x0000",
        "0x000A",
        "0x000B",
        "0x000D",
        "0x0016",
        "0x0017",
        "0x0023"
      ]
    },
    "legacy_version": "TLS 1.2",
    "offered_cipher_suites": [
      {
        "id": "0xC030",
        "name": "ECDHE-RSA-AES256-GCM-SHA384"
      },
      {
        "id": "0x00FF",
        "name": "UNKNOWN"
      }
    ],
    "random": "...",
    "session_id": ""
  }
}
```

Important fields:

```text
legacy_version
random
session_id
compression_methods[]
offered_cipher_suites[]
extensions.types[]
extensions.sni
extensions.supported_groups[]
extensions.signature_algorithms[]
```

Registries are intentionally extensible. Unknown cipher/group IDs must not crash parsing.

---

# 15. TLS 1.2 ServerHello Schema

Observed:

```json
{
  "server_hello": {
    "cipher_suite": {
      "id": "0xC030",
      "name": "ECDHE-RSA-AES256-GCM-SHA384"
    },
    "compression_method": 0,
    "extensions": {
      "types": [
        "0x000B",
        "0x0017",
        "0x0023",
        "0xFF01"
      ]
    },
    "legacy_version": "TLS 1.2",
    "random": "...",
    "session_id": ""
  }
}
```

Preserve both:

```text
cipher_suite.id
cipher_suite.name
```

The raw IANA-style identifier is important forensic evidence.

---

# 16. Key Exchange Schema

Observed:

```json
{
  "key_exchange": {
    "forward_secrecy": true,
    "group": "x25519",
    "mechanism": "ECDHE"
  }
}
```

Expected semantic concepts:

```text
mechanism:
  RSA
  DHE
  ECDHE
  unknown

group:
  curve/group name when available

forward_secrecy:
  true
  false
  unknown
```

The parser reports the technical fact. It does not assign a security score here.

---

# 17. Certificate Availability Schema

Observed:

```json
{
  "certificate_availability": {
    "confidence": "high",
    "evidence": [
      "2 DER certificate(s) observed in TLS Certificate handshake"
    ],
    "frames": [1, 2, 3],
    "value": "available"
  }
}
```

Possible semantic values include:

```text
available
encrypted_or_unavailable
unavailable
```

TLS 1.3 requirement:

After ServerHello, the TLS 1.3 handshake is encrypted. Therefore a passive PCAP without session keys may expose ClientHello/ServerHello but not the subsequent Certificate bytes.

Do NOT label TLS 1.3 certificates as inherently impossible.

Correct behavior:

```text
certificate_status = encrypted_or_unavailable
reason = TLS 1.3 handshake encrypted; no session keys supplied
```

Future architecture may support key-log/session-secret input for TLS 1.3 decryption.

---

# 18. X.509 Certificate Schema

Each observed certificate appears under:

```text
sessions[].certificates[]
```

Verified structure:

```json
{
  "basic_constraints": {
    "ca": false,
    "path_length": null
  },
  "ca_status": false,
  "extended_key_usage": [
    "1.3.6.1.5.5.7.3.1"
  ],
  "fingerprint_sha256": "...",
  "issuer": "...",
  "key_usage": [
    "digital_signature",
    "key_encipherment"
  ],
  "not_after": "...",
  "not_before": "...",
  "public_key_algorithm": "RSAPublicKey",
  "public_key_size": 2048,
  "san": [
    "DNS:mail.securemailscope.local",
    "DNS:localhost"
  ],
  "serial_number": "...",
  "signature_algorithm": "1.2.840.113549.1.1.11",
  "subject": "...",
  "validation": {
    "expired": false,
    "issuer_relationship_verified": true,
    "local_trust_evaluated": false,
    "not_yet_valid": false,
    "observed_chain_complete": true,
    "self_signed": false
  },
  "version": "v3"
}
```

Certificate facts to preserve:

```text
version
serial_number
subject
issuer

not_before
not_after

signature_algorithm

public_key_algorithm
public_key_size

san[]

basic_constraints.ca
basic_constraints.path_length

key_usage[]
extended_key_usage[]

ca_status
fingerprint_sha256

validation.expired
validation.not_yet_valid
validation.self_signed
validation.issuer_relationship_verified
validation.observed_chain_complete
validation.local_trust_evaluated
```

Do not conflate:

```text
cryptographic/structural certificate validation
```

with:

```text
local operating-system trust-store validation
```

The existing field `local_trust_evaluated` explicitly represents whether a local trust-store decision was actually made.

---

# 19. Certificate Validation Semantics

The parser validates facts observable from the supplied chain and certificate metadata.

Current examples:

```text
expired
not_yet_valid
self_signed
issuer_relationship_verified
observed_chain_complete
local_trust_evaluated
```

Do not silently convert these into vulnerability severities.

Risk severity belongs in `risk_analysis.py`.

---

# 20. Forensic Warnings

A session has:

```text
warnings[]
```

The parser should use warnings for parse limitations, ambiguity, unsupported constructs, missing ranges, unavailable TLS 1.3 encrypted content, or similar technical conditions.

Warnings are not necessarily vulnerabilities.

Do not use `warnings` as a hidden risk-scoring channel.

---

# 21. Current Verified Parser Output

The current real fixture produced:

```text
schema_version = 1.0

session_id = tcp-0001
parse_status = complete

protocol = SMTP
encryption = STARTTLS

TLS version = TLS 1.2
cipher = 0xC030 / ECDHE-RSA-AES256-GCM-SHA384

key exchange = ECDHE
group = x25519
forward secrecy = true

certificates = 2

leaf:
  RSA 2048
  CN=mail.securemailscope.local,O=SecureMailScope,C=US
  SAN = mail.securemailscope.local, localhost

reassembly:
  complete
  no duplicate segments
  no retransmissions
  no out-of-order segments
  no missing ranges
```

This is the baseline parser regression fixture and should continue to parse successfully after future changes.

---

# 22. Parser Tests

The parser implementation reported:

```text
python -m unittest discover -v
```

Result:

```text
9 tests passed
```

Coverage includes:

- TCP reassembly
- missing TCP data
- duplicate segments
- out-of-order data
- malformed TLS
- email protocol detection
- STARTTLS detection
- cipher normalization
- X.509 extraction
- PCAP integration

Do not remove these tests when extending the parser.

---

# 23. Known Parser Limitations

### TLS decryption

There is no TLS decryption or key recovery.

TLS 1.3 post-ServerHello certificates cannot be parsed from an ordinary passive capture when the relevant handshake bytes are encrypted and no session keys are provided.

Future design may accept session secrets/key logs.

### Missing TCP data

The parser intentionally does not invent contiguous application data when sequence gaps exist.

It stops parsing beyond the first missing required range and reports partial/incomplete state.

### Protocol registries

Cipher/group registries are extensible but not exhaustive.

Unknown identifiers must remain representable rather than becoming fatal parser errors.

### PCAP size

Prototype scope explicitly does NOT require special optimization for 10–25 GB captures.

Loading the PCAP into memory is acceptable for this stage.

Correct TCP reconstruction and clear architecture are more important than large-PCAP optimization right now.

---

# 24. TLS Scenario Corpus — Intended Matrix

The test corpus should cover at least:

1. TLS 1.2 + current strong baseline
2. TLS 1.2 + deliberately weak/legacy cipher, only when technically supported
3. TLS 1.2 + expired certificate
4. TLS 1.2 + wrong SAN / hostname mismatch
5. TLS 1.2 + weak/short public key where technically possible
6. TLS 1.3 + modern cipher
7. Implicit TLS SMTP — direct TLS, no STARTTLS

For weak/legacy cases:

- Do not fake PCAPs.
- Do not alter PCAP bytes merely to make a parser result look weak.
- If the installed Postfix/OpenSSL stack refuses an obsolete cipher or certificate configuration, document the limitation and use the closest valid technical case.

For implicit TLS:

- It must be a genuine direct TLS SMTP connection.
- Do not merely relabel a STARTTLS capture as implicit TLS.

---

# 25. Scenario Framework State

The scenario extension was implemented around two selectors:

```text
TLS_SCENARIO
CERT_PROFILE
```

Concept:

```text
TLS_SCENARIO
  → protocol/cipher policy

CERT_PROFILE
  → isolated CA-signed certificate directory/profile
```

The default strong TLS 1.2 baseline must remain unchanged.

The scenario framework also adds/configures:

- TLS policy variants
- certificate profiles
- direct TLS SMTP
- configurable test client
- implicit-TLS port mapping, including `2465`

At the time of the latest Codex report, Docker Desktop/Linux engine availability prevented full validation of the new scenario captures.

Therefore:

```text
Scenario framework implementation: present
Scenario framework implementation: present

Baseline scenario generation: verified
Baseline scenario parser validation: verified

Other scenario PCAP generation: pending verification
Other scenario parser validation: pending verificationScenario PCAP generation: not yet fully verified
Scenario parser validation: not yet fully verified
```

Do not claim those captures exist until they are actually generated and parsed successfully.

---

# 25.1 Scenario Runner — Verified Startup/Capture Flow

`scripts/run_tls_scenario.py` was debugged and corrected.

The runner had three orchestration issues:

1. `docker compose up -d` returned before Postfix had finished initialization and was accepting SMTP connections.
2. The SMTP client could therefore run before Postfix was ready.
3. Terminating tshark immediately after the SMTP client could leave an incomplete PCAP because tshark had not flushed its capture buffers.
4. A finite tshark capture window could also expire while waiting for Postfix readiness.

The corrected runner now:

1. starts/recreates Postfix
2. waits for internal Postfix readiness without creating an SMTP connection
3. starts tshark
4. waits 2 seconds
5. runs `send_test_email.py`
6. allows tshark's bounded capture to finish normally after successful SMTP execution
7. forcibly cleans up tshark only on failure
8. validates the resulting PCAP
9. runs the parser

This sequence is now verified on Windows with tshark interface 8.

# 26. Files and Responsibilities

```text
analyzer/
  __init__.py
  parser.py
    Main passive forensic parser.
    TCP flow/reassembly.
    Protocol detection.
    STARTTLS/implicit TLS.
    TLS parsing.
    X.509 extraction.
    JSON output.

tests/
  test_parser.py
    Parser unit/integration tests.

scripts/
  generate_certs.sh
    Certificate/PKI generation.

  send_test_email.py
    Configurable SMTP test client.


  run_tls_scenario.py
    Scenario orchestration/test-capture runner.
    Generates real TLS scenario PCAPs.
    Controls certificate profile and TLS policy.
    Starts Postfix and tshark.
    Waits for Postfix readiness.
    Runs send_test_email.py.
    Validates capture and invokes parser.  

postfix/
  tls-config.sh
    Container-side Postfix/TLS configuration.

capture/
  postfix_tls12.pcapng
    Verified baseline PCAP.

capture/
  parser_result.json
    Parser output for baseline fixture.

Dockerfile
docker-compose.yml
requirements.txt
```

Future components:

```text
risk_analysis.py
recommendation.py
```

Potential future organization:

```text
analyzer/
  parser.py
  risk_analysis.py
  recommendation.py

ml/
  anomaly detection / future models

reports/
  JSON/PDF/HTML generation

dashboard/
  future UI
```

Do not introduce this structure prematurely if the current repository already has a different stable layout.

---

# 27. Strict Separation of Concerns

## `analyzer/parser.py`

Responsible for:

- What is in the PCAP?
- What protocol is this?
- How was TCP reconstructed?
- Was STARTTLS observed?
- Is it implicit TLS?
- What TLS version was negotiated?
- What cipher was selected?
- What key exchange/group was observable?
- Was forward secrecy technically present?
- What certificates were actually observed?
- What certificate properties were parsed?
- What evidence supports every important field?
- What could not be observed due to encryption/missing data?

NOT responsible for:

- risk score
- severity
- exploitability score
- AI/ML classification
- mitigation recommendations
- executive summaries
- dashboard presentation

## `risk_analysis.py`

Takes structured parser JSON as input.

Responsibilities:

- deterministic cryptographic/security rules
- posture/risk classification
- weak/deprecated protocol detection
- certificate risk
- configuration weaknesses
- prioritization
- eventual AI-assisted contextual risk analysis

Do not make the parser depend on `risk_analysis.py`.

## `recommendation.py`

Consumes risk-analysis results.

Responsibilities:

- concise human-readable findings
- remediation recommendations
- prioritization
- mapping findings to technical remediation

It should not need to parse raw packets.

## Future anomaly ML

Anomalous TLS behavior should be a separate future module.

Do not mix anomaly-model training/inference into the TCP/TLS parser.

---

# 28. Risk Analysis Design Direction

The project requirement includes AI-assisted cryptographic risk analysis.

The intended architecture is:

```text
Parser facts
    ↓
Deterministic security rules
    ↓
AI-assisted contextual interpretation
    ↓
Risk classification / posture
    ↓
Recommendations
```

AI should augment deterministic evidence rather than freely invent technical facts.

The exact scoring rubric/weights have NOT been finalized yet.

Do not invent arbitrary production weights without an explicit design/research step.

The parser already provides the technical evidence required for future scoring.

---

# 29. Regression Contract for Future Agents

Before changing parser behavior:

1. Run the existing test suite.
2. Parse the known-good TLS 1.2 baseline.
3. Confirm:
   - `schema_version == "1.0"`
   - session exists
   - protocol is SMTP
   - encryption is STARTTLS
   - TLS version is TLS 1.2
   - cipher ID is `0xC030`
   - cipher name is `ECDHE-RSA-AES256-GCM-SHA384`
   - key exchange is ECDHE
   - group is x25519
   - forward secrecy is true
   - two certificates are extracted
   - leaf certificate is RSA 2048
   - reassembly status is complete
   - missing ranges are empty
4. Do not silently rename existing JSON fields.
5. Add fields compatibly rather than replacing established fields.
6. Keep evidence/frame provenance.
7. Preserve partial-session behavior.
8. One malformed session must not terminate analysis of the entire PCAP.



Before modifying `scripts/run_tls_scenario.py`:

1. Do not remove the Postfix readiness check.
2. Do not start the finite tshark capture until Postfix is ready.
3. Preserve the 2-second delay between tshark startup and SMTP client execution.
4. After successful SMTP execution, allow tshark to terminate/flush normally.
5. On failure, ensure tshark is cleaned up.
6. Validate that the resulting PCAP contains actual SMTP/TLS traffic before accepting the scenario.

---

# 30. Important Engineering Rules

### Do not fake forensic evidence

PCAPs must be real captures generated from actual protocol behavior.

Never modify packet bytes simply to manufacture a desired parser result.

### Preserve observable facts

Prefer:

```text
unknown
unavailable
encrypted_or_unavailable
```

over fabricated values.

### Keep raw identifiers

For cryptographic identifiers, preserve:

```text
raw ID
normalized human-readable name
```

where both are available.

### Do not over-score in the parser

A parser should say:

```text
TLS 1.2
ECDHE-RSA-AES256-GCM-SHA384
RSA 2048
certificate expired = false
```

Risk analysis should decide whether those properties are weak, acceptable, high risk, etc.

### Do not port-sniff blindly

Ports are useful hints, not sufficient protocol evidence.

### Do not equate encryption with decryption capability

A parser can detect TLS without being able to decrypt TLS application data.

---

# 31. Baseline Parser Command

From the repository root:

```powershell
python analyzer\parser.py capture\postfix_tls12.pcapng --output capture\parser_result.json
```

This baseline command should remain functional.

---

# 32. Current Next Steps


```

### Then

Build:

```text
risk_analysis.py
```

using the parser's structured JSON contract.

### Then

Build:

```text
recommendation.py
```

on top of risk-analysis output.

### Later

Add:

```text
AI-assisted contextual scoring
TLS anomaly detection
JSON/PDF/HTML reports
interactive dashboard
```

---

# 33. Handoff Instruction for Antigravity

Before making code changes:

1. Inspect the repository and existing implementation.
2. Treat the current parser JSON structure as the compatibility contract.
3. Read existing tests before refactoring.
4. Do not rewrite working Postfix infrastructure without a concrete reason.
5. Do not rewrite the parser merely to change architecture names.
6. Preserve the verified baseline fixture.
7. Clearly separate:
   - verified behavior
   - implemented but unverified behavior
   - planned future behavior
8. When adding scenario fixtures, use real captures and real parser output.
9. When a protocol feature cannot be observed because of TLS encryption or missing session keys, report it explicitly rather than inventing data.
10. Keep future risk/AI/reporting work downstream of parser JSON.

The current parser output is the ground truth for the schema contract. Future modules should consume this schema rather than reaching back into the PCAP parser for technical facts.
