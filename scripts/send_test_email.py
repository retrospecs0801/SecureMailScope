#!/usr/bin/env python3
"""Send a CA-verified STARTTLS or direct-TLS SMTP test message."""

from __future__ import annotations

import argparse
import smtplib
import ssl
import sys
from email.message import EmailMessage
from pathlib import Path


def arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="localhost")
    parser.add_argument("--port", type=int, default=2525)
    parser.add_argument("--mode", choices=("starttls", "implicit"), default="starttls")
    parser.add_argument("--tls-version", choices=("1.0", "1.2", "1.3"), default="1.2")
    parser.add_argument("--cipher", help="TLS <=1.2 OpenSSL cipher list; TLS 1.3 suites are provider-selected")
    parser.add_argument("--ca-file", type=Path, default=Path("certs/ca.crt"))
    parser.add_argument("--sender", default="sender@securemailscope.local")
    parser.add_argument("--recipient", default="recipient@securemailscope.local")
    parser.add_argument("--subject", default="SecureMailScope TLS 1.2 SMTP test")
    parser.add_argument("--expect-verification-failure", action="store_true", help="Treat certificate verification failure as the expected test result")
    parser.add_argument("--insecure-test-only", action="store_true", help="Disable verification explicitly for a local negative-certificate test")
    return parser.parse_args()


def main() -> int:
    args = arguments()
    if not args.ca_file.is_file():
        print(f"CA certificate not found: {args.ca_file}", file=sys.stderr)
        return 2

    context = ssl.create_default_context(cafile=str(args.ca_file))
    version = {
        "1.0": ssl.TLSVersion.TLSv1,
        "1.2": ssl.TLSVersion.TLSv1_2,
        "1.3": ssl.TLSVersion.TLSv1_3,
    }[args.tls_version]
    context.minimum_version = version
    context.maximum_version = version
    if args.insecure_test_only:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        print("Certificate verification: deliberately disabled (--insecure-test-only)")
    if args.cipher and args.tls_version != "1.3":
        context.set_ciphers(args.cipher)
    elif args.cipher and args.tls_version == "1.3":
        raise RuntimeError(
            "TLS 1.3 cipher selection is unsupported by this Python/OpenSSL runtime: "
            "SSLContext.set_ciphersuites() is unavailable"
        )

    message = EmailMessage()
    message["From"] = args.sender
    message["To"] = args.recipient
    message["Subject"] = args.subject
    message.set_content("SecureMailScope local SMTP STARTTLS TLS 1.2 test message.")

    try:
        connection = (
            smtplib.SMTP_SSL(args.host, args.port, timeout=15, context=context)
            if args.mode == "implicit"
            else smtplib.SMTP(args.host, args.port, timeout=15)
        )
        with connection as smtp:
            if args.mode == "starttls":
                code, response = smtp.ehlo()
                print(f"EHLO: {code} {response.decode(errors='replace')}")
                if not smtp.has_extn("starttls"):
                    raise RuntimeError("server did not advertise STARTTLS")
                code, response = smtp.starttls(context=context)
                print(f"STARTTLS: {code} {response.decode(errors='replace')}")
            else:
                print("Implicit TLS: connected before SMTP dialogue")
            tls_socket = smtp.sock
            print(f"TLS version: {tls_socket.version()}")
            print(f"TLS cipher: {tls_socket.cipher()[0]}")
            peer = tls_socket.getpeercert()
            print(f"Certificate subject: {peer.get('subject')}")
            print(f"Certificate issuer: {peer.get('issuer')}")
            code, response = smtp.ehlo()
            print(f"EHLO after TLS: {code} {response.decode(errors='replace')}")
            refused = smtp.send_message(message)
            if refused:
                raise RuntimeError(f"recipient refusals: {refused}")
            print("Message accepted: 250")
        print("QUIT: successful")
    except ssl.SSLCertVerificationError as exc:
        if args.expect_verification_failure:
            print(f"Expected certificate verification failure: {exc}")
            return 0
        print(f"SMTP TLS test failed: {exc}", file=sys.stderr)
        return 1
    except (OSError, smtplib.SMTPException, ssl.SSLError, RuntimeError) as exc:
        print(f"SMTP TLS test failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
