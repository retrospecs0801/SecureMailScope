"""Build the scoped risk-scoring dataset from labeled scenario fixtures.

This dataset intentionally covers only the low and critical extremes for the
prototype. A model trained on ~15-20 examples cannot be trusted to draw
reliable boundaries in the ambiguous moderate/high middle tier - better to be
honest that the prototype demonstrates clean separation of clearly-secure vs
clearly-broken configurations, with moderate/high classification as explicit
future work, than to claim 4-class coverage on a dataset too small to support it.

The output label taxonomy is the full four-class set {low, moderate, high,
critical}; this version intentionally populates only low and critical rows.
"""

from __future__ import annotations

import csv
import json
import subprocess
import sys
from collections import Counter
from pathlib import Path

from features import extract_risk_features
from scripts.run_tls_scenario import ROOT, SCENARIOS

VALID_LABELS = {"low", "moderate", "high", "critical"}
OUTPUT_PATH = ROOT / "datasets" / "risk_scoring_v1.csv"


def _load_or_generate(scenario_name: str, pcap_name: str) -> dict:
    json_path = ROOT / "capture" / Path(pcap_name).with_suffix(".json")
    if not json_path.is_file():
        subprocess.run((sys.executable, "scripts/run_tls_scenario.py", scenario_name), cwd=ROOT, check=True)
    if not json_path.is_file():
        raise FileNotFoundError(f"scenario did not produce parser JSON: {json_path}")
    payload = json.loads(json_path.read_text(encoding="utf-8"))
    return payload["sessions"][0]


def build_dataset() -> Counter:
    labeled = [(name, scenario) for name, scenario in SCENARIOS.items() if scenario.label]
    invalid = {scenario.label for _, scenario in labeled} - VALID_LABELS
    if invalid:
        raise ValueError(f"invalid scenario labels: {sorted(invalid)}")

    rows = []
    skipped = []
    for scenario_name, scenario in labeled:
        json_path = ROOT / "capture" / Path(scenario.pcap).with_suffix(".json")
        try:
            session = _load_or_generate(scenario_name, scenario.pcap)
        except (FileNotFoundError, subprocess.CalledProcessError, RuntimeError) as exc:
            skipped.append(f"{scenario_name} ({exc})")
            continue
        row = extract_risk_features(session)
        row.update({"label": scenario.label, "scenario_name": scenario_name})
        rows.append(row)

    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = [*extract_risk_features({}).keys(), "label", "scenario_name"]
    with OUTPUT_PATH.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    counts = Counter(row["label"] for row in rows)
    print(f"Wrote {len(rows)} rows to {OUTPUT_PATH.relative_to(ROOT)}")
    if skipped:
        print(f"Skipped labeled scenarios without a parsed fixture: {', '.join(skipped)}")
    for label in ("low", "moderate", "high", "critical"):
        print(f"{label}: {counts.get(label, 0)} rows")
    print("moderate: 0 rows, high: 0 rows - out of scope for this dataset version, see build_training_dataset.py docstring")
    return counts


if __name__ == "__main__":
    build_dataset()
