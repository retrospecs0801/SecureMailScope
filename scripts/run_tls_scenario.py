#!/usr/bin/env python3
"""Generate one real local SMTP/TLS PCAP fixture and parse it.

The prototype dataset intentionally covers only the low and critical extremes.
A model trained on ~15-20 examples cannot be trusted to draw reliable
boundaries in the ambiguous moderate/high middle tier. It is better to be
honest that this prototype demonstrates clearly-secure versus clearly-broken
configurations, with moderate/high classification as explicit future work,
than to claim four-class coverage from a dataset too small to support it.
"""

from __future__ import annotations

import argparse
import os
import re
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


@dataclass(frozen=True)
class Scenario:
    tls_scenario: str
    certificate_profile: str
    pcap: str
    client_args: tuple[str, ...]
    label: str = ""


SCENARIOS = {
    "tls12_strong": Scenario("tls12_strong", "baseline", "postfix_tls12.pcapng", ("--tls-version", "1.2", "--cipher", "ECDHE-RSA-AES256-GCM-SHA384"), "low"),
    "tls12_aead_ecdsa": Scenario("tls12_aead", "ecdsa", "postfix_tls12_aead_ecdsa.pcapng", ("--tls-version", "1.2", "--cipher", "ECDHE-ECDSA-AES128-GCM-SHA256"), "low"),
    "tls13_modern": Scenario("tls13_modern", "baseline", "postfix_tls13.pcapng", ("--tls-version", "1.3"), "low"),
    # Python 3.13/OpenSSL 3.0.16 in this environment has no set_ciphersuites();
    # do not claim a ChaCha20 row when the requested suite cannot be forced.
    "tls12_rsa4096": Scenario("tls12_strong", "rsa4096", "postfix_tls12_rsa4096.pcapng", ("--tls-version", "1.2", "--cipher", "ECDHE-RSA-AES256-GCM-SHA384"), "low"),
    "tls12_valid_window": Scenario("tls12_strong", "baseline", "postfix_tls12_valid_window.pcapng", ("--tls-version", "1.2", "--cipher", "ECDHE-RSA-AES256-GCM-SHA384"), "low"),
    "tls12_valid_san": Scenario("tls12_strong", "baseline", "postfix_tls12_valid_san.pcapng", ("--tls-version", "1.2", "--cipher", "ECDHE-RSA-AES256-GCM-SHA384"), "low"),
    "tls12_valid_serial": Scenario("tls12_strong", "baseline", "postfix_tls12_valid_serial.pcapng", ("--tls-version", "1.2", "--cipher", "ECDHE-RSA-AES256-GCM-SHA384"), "low"),
    "tls12_expired": Scenario("tls12_strong", "expired", "postfix_tls12_expired_cert.pcapng", ("--tls-version", "1.2", "--cipher", "ECDHE-RSA-AES256-GCM-SHA384", "--ca-file", "certs/scenarios/expired/ca.crt", "--expect-verification-failure"), "critical"),
    "tls12_expired_ecdsa": Scenario("tls12_aead", "expired_ecdsa", "postfix_tls12_expired_ecdsa.pcapng", ("--tls-version", "1.2", "--cipher", "ECDHE-ECDSA-AES128-GCM-SHA256", "--ca-file", "certs/scenarios/expired_ecdsa/ca.crt", "--expect-verification-failure"), "critical"),
    "tls12_expired_rsa4096": Scenario("tls12_strong", "expired_rsa4096", "postfix_tls12_expired_rsa4096.pcapng", ("--tls-version", "1.2", "--cipher", "ECDHE-RSA-AES256-GCM-SHA384", "--ca-file", "certs/scenarios/expired_rsa4096/ca.crt", "--expect-verification-failure"), "critical"),
    "tls12_expired_weak_sig": Scenario("tls12_strong", "expired_sha1", "postfix_tls12_expired_weak_sig.pcapng", ("--tls-version", "1.2", "--cipher", "ECDHE-RSA-AES256-GCM-SHA384", "--ca-file", "certs/scenarios/expired_sha1/ca.crt", "--expect-verification-failure"), "critical"),
    "tls10_deprecated": Scenario("tls10_deprecated", "baseline", "postfix_tls10_deprecated.pcapng", ("--tls-version", "1.0", "--cipher", "AES128-SHA:@SECLEVEL=0", "--insecure-test-only"), "critical"),
    "tls12_rsa1024": Scenario("tls12_weak_key", "rsa1024", "postfix_tls12_rsa1024.pcapng", ("--tls-version", "1.2", "--cipher", "ECDHE-RSA-AES256-GCM-SHA384:@SECLEVEL=0", "--ca-file", "certs/scenarios/rsa1024/ca.crt", "--insecure-test-only"), "critical"),
    "tls12_self_signed_leaf": Scenario("tls12_strong", "self_signed_leaf", "postfix_tls12_self_signed_leaf.pcapng", ("--tls-version", "1.2", "--cipher", "ECDHE-RSA-AES256-GCM-SHA384", "--insecure-test-only"), "critical"),
    "sha1_signature": Scenario("tls12_strong", "sha1", "postfix_sha1_signature.pcapng", ("--tls-version", "1.2", "--cipher", "ECDHE-RSA-AES256-GCM-SHA384", "--insecure-test-only"), "critical"),
    "tls12_legacy": Scenario("tls12_legacy", "baseline", "postfix_tls12_legacy_aes128_sha.pcapng", ("--tls-version", "1.2", "--cipher", "AES128-SHA")),
    "tls12_wrong_san": Scenario("tls12_strong", "wrong_san", "postfix_tls12_wrong_san.pcapng", ("--tls-version", "1.2", "--cipher", "ECDHE-RSA-AES256-GCM-SHA384", "--ca-file", "certs/scenarios/wrong_san/ca.crt", "--expect-verification-failure")),
    "implicit_tls12": Scenario("implicit_tls12", "baseline", "postfix_implicit_tls12.pcapng", ("--mode", "implicit", "--port", "2465", "--tls-version", "1.2", "--cipher", "ECDHE-RSA-AES256-GCM-SHA384")),
}


def command(*parts: str, env: dict[str, str] | None = None) -> None:
    completed = subprocess.run(parts, cwd=ROOT, env=env, text=True)
    if completed.returncode:
        raise RuntimeError(f"command failed ({completed.returncode}): {' '.join(parts)}")


def tshark_loopback(tshark: str) -> str:
    output = subprocess.check_output((tshark, "-D"), text=True, encoding="utf-8", errors="replace")
    match = re.search(r"^(\d+)\. .*Loopback", output, re.MULTILINE | re.IGNORECASE)
    if not match:
        raise RuntimeError("No tshark loopback capture interface found; run tshark -D and use --interface")
    return match.group(1)


def wait_for_postfix(environment: dict[str, str]) -> None:
    deadline = time.monotonic() + 45
    while time.monotonic() < deadline:
        result = subprocess.run(
            ("docker", "compose", "exec", "-T", "postfix", "postfix", "status"),
            cwd=ROOT,
            env=environment,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        if result.returncode == 0:
            return
        time.sleep(1)
    raise RuntimeError("Postfix did not finish starting within 45 seconds")


def stop_previous_postfix(environment: dict[str, str]) -> None:
    command("docker", "compose", "stop", "postfix", env=environment)
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        running = subprocess.run(
            ("docker", "compose", "ps", "-q", "--status", "running", "postfix"),
            cwd=ROOT,
            env=environment,
            capture_output=True,
            text=True,
        )
        if not running.stdout.strip():
            command("docker", "compose", "rm", "-f", "postfix", env=environment)
            return
        time.sleep(1)
    raise RuntimeError("previous Postfix container did not stop within 15 seconds")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("scenario", choices=sorted(SCENARIOS))
    parser.add_argument("--interface", help="tshark interface; defaults to the local loopback interface")
    args = parser.parse_args(argv)
    selected = SCENARIOS[args.scenario]
    environment = os.environ.copy()
    environment.update({"TLS_SCENARIO": selected.tls_scenario, "CERT_PROFILE": selected.certificate_profile})
    tshark = shutil.which("tshark")
    if not tshark:
        raise SystemExit("tshark is required to generate a fixture; it was not found on PATH")

    command("docker", "compose", "--profile", "tools", "run", "--rm", "certgen", env=environment)
    stop_previous_postfix(environment)
    command("docker", "compose", "up", "-d", "--force-recreate", "postfix", env=environment)
    port = 2465 if "--mode" in selected.client_args else 2525
    wait_for_postfix(environment)
    capture_path = ROOT / "capture" / selected.pcap
    capture_path.unlink(missing_ok=True)
    interface = args.interface or tshark_loopback(tshark)
    capture = subprocess.Popen(
        (tshark, "-i", interface, "-f", f"tcp port {port}", "-F", "pcapng", "-a", "duration:8", "-w", str(capture_path)),
        cwd=ROOT,
        env=environment,
    )
    try:
        time.sleep(2)
        command(sys.executable, "scripts/send_test_email.py", *selected.client_args, env=environment)
        capture.wait(timeout=20)
    finally:
        if capture.poll() is None:
            capture.terminate()
            capture.wait(timeout=5)
    if not capture_path.is_file() or capture_path.stat().st_size <= 460:
        raise RuntimeError(f"tshark did not produce traffic capture: {capture_path}")
    command(
        sys.executable,
        "analyzer/parser.py",
        str(capture_path),
        "--output",
        str(capture_path.with_suffix(".json")),
        env=environment,
    )
    print(f"PCAP: {capture_path.relative_to(ROOT)}")
    print(f"Parser JSON: {capture_path.with_suffix('.json').relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
