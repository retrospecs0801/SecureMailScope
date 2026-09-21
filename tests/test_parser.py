import unittest
from pathlib import Path

from analyzer.parser import (
    CIPHER_SUITES,
    ForensicParser,
    Segment,
    TCPDirection,
    TLSParser,
    encryption_mode,
    identify_email_protocol,
)


ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "capture" / "postfix_tls12.pcapng"


class TCPReassemblyTests(unittest.TestCase):
    def test_out_of_order_segments_are_reassembled_by_sequence(self):
        stream = TCPDirection()
        stream.add(Segment(105, b" world", 2, 2.0, "PA"))
        stream.add(Segment(100, b"hello", 1, 1.0, "PAF"))
        result = stream.reassemble()
        self.assertEqual(result.data, b"hello world")
        self.assertEqual(result.status, "complete")
        self.assertGreaterEqual(result.out_of_order, 1)

    def test_duplicate_and_missing_segments_are_explicit(self):
        stream = TCPDirection()
        stream.add(Segment(100, b"hello", 1, 1.0, "PA"))
        stream.add(Segment(100, b"hello", 2, 2.0, "PA"))
        stream.add(Segment(110, b"world", 3, 3.0, "PAF"))
        result = stream.reassemble()
        self.assertEqual(result.data, b"hello")
        self.assertEqual(result.status, "missing_segments")
        self.assertEqual(result.duplicate_segments, 1)
        self.assertEqual(result.missing_ranges[0]["length"], 5)

    def test_truncated_tls_record_is_not_treated_as_a_handshake(self):
        result = TLSParser().parse(b"\x16\x03\x03\x00\x20short", b"")
        self.assertFalse(result["detected"])


class ClassifierTests(unittest.TestCase):
    def test_smtp_starttls_requires_protocol_and_tls_evidence(self):
        client = b"EHLO client.example\r\nSTARTTLS\r\n\x16\x03\x03\x00\x01x"
        protocol = identify_email_protocol(client, b"220 ready\r\n", [1, 2])
        mode = encryption_mode(protocol.value, client, b"", True, [1, 2])
        self.assertEqual(protocol.value, "SMTP")
        self.assertEqual(protocol.confidence, "high")
        self.assertEqual(mode.value, "STARTTLS")

    def test_implicit_tls_is_not_port_based(self):
        mode = encryption_mode("unknown", b"\x16\x03\x03\x00\x01x", b"", True, [1])
        self.assertEqual(mode.value, "implicit_tls")
        self.assertEqual(mode.confidence, "medium")

    def test_cipher_registry_normalizes_fixture_cipher(self):
        self.assertEqual(CIPHER_SUITES[0xC030], "ECDHE-RSA-AES256-GCM-SHA384")


@unittest.skipUnless(FIXTURE.exists(), "Postfix TLS integration fixture is absent")
class FixtureIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.result = ForensicParser().parse_file(FIXTURE)
        cls.session = cls.result["sessions"][0]

    def test_flow_and_protocol(self):
        self.assertEqual(len(self.result["sessions"]), 1)
        self.assertEqual(self.session["parse_status"], "complete")
        self.assertEqual(self.session["email_protocol"]["value"], "SMTP")
        self.assertEqual(self.session["encryption"]["value"], "STARTTLS")

    def test_tls12_and_cipher_extraction(self):
        tls = self.session["tls"]
        self.assertEqual(tls["parser"], "legacy_tls")
        self.assertEqual(tls["negotiated_version"], "TLS 1.2")
        self.assertEqual(tls["server_hello"]["cipher_suite"], {"id": "0xC030", "name": "ECDHE-RSA-AES256-GCM-SHA384"})
        self.assertEqual(tls["key_exchange"]["mechanism"], "ECDHE")
        self.assertTrue(tls["key_exchange"]["forward_secrecy"])

    def test_real_x509_chain_extraction(self):
        certificates = self.session["certificates"]
        self.assertGreaterEqual(len(certificates), 1)
        leaf = certificates[0]
        self.assertIn("CN=mail.securemailscope.local", leaf["subject"])
        self.assertIn("DNS:localhost", leaf["san"])
        self.assertEqual(leaf["public_key_size"], 2048)
        self.assertFalse(leaf["ca_status"])
        self.assertEqual(self.session["certificate_availability"]["value"], "available")


if __name__ == "__main__":
    unittest.main()
