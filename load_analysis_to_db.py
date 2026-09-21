"""Load parser JSON and deterministic analysis into sessions.db."""

from __future__ import annotations

import argparse
import json
import sqlite3
from pathlib import Path

from analyzer.analysis import analyze_session

DEFAULT_DATABASE = Path(__file__).resolve().with_name("sessions.db")

SCHEMA = """
CREATE TABLE IF NOT EXISTS sessions (
    session_id TEXT PRIMARY KEY, protocol TEXT, tls_version TEXT, server_port INTEGER,
    client_ip TEXT, server_ip TEXT, timestamp TEXT, deterministic_score INTEGER NOT NULL,
    deterministic_risk TEXT NOT NULL, confidence_level TEXT NOT NULL,
    confidence_reasons TEXT, ai_score REAL, anomaly_score REAL, final_risk TEXT, priority INTEGER
);
CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT, session_id TEXT NOT NULL, "check" TEXT NOT NULL,
    observed_value TEXT, risk_level TEXT, reference TEXT, rationale TEXT, confidence TEXT,
    FOREIGN KEY (session_id) REFERENCES sessions(session_id)
);
"""


def load_files(paths: list[str], database: str | Path = DEFAULT_DATABASE) -> None:
    with sqlite3.connect(database) as connection:
        connection.executescript(SCHEMA)
        legacy_ids = [
            row[0]
            for row in connection.execute(
                "SELECT session_id FROM sessions WHERE instr(session_id, ':') = 0"
            )
        ]
        if legacy_ids:
            placeholders = ",".join("?" for _ in legacy_ids)
            connection.execute(
                f"DELETE FROM findings WHERE session_id IN ({placeholders})",
                legacy_ids,
            )
            connection.execute(
                f"DELETE FROM sessions WHERE session_id IN ({placeholders})",
                legacy_ids,
            )
        for raw_path in paths:
            source_path = Path(raw_path)
            payload = json.loads(source_path.read_text(encoding="utf-8"))
            for session in payload.get("sessions", []):
                analysis = analyze_session(session)
                database_session_id = f"{source_path.stem}:{analysis['session_id']}"
                network = session.get("network", {})
                client = network.get("client", {})
                server = network.get("server", {})
                connection.execute(
                    """INSERT INTO sessions
                    (session_id, protocol, tls_version, server_port, client_ip, server_ip,
                     timestamp, deterministic_score, deterministic_risk, confidence_level,
                     confidence_reasons, final_risk)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(session_id) DO UPDATE SET protocol=excluded.protocol,
                    tls_version=excluded.tls_version, server_port=excluded.server_port,
                    client_ip=excluded.client_ip, server_ip=excluded.server_ip,
                    timestamp=excluded.timestamp, deterministic_score=excluded.deterministic_score,
                    deterministic_risk=excluded.deterministic_risk,
                    confidence_level=excluded.confidence_level,
                    confidence_reasons=excluded.confidence_reasons, final_risk=excluded.final_risk""",
                    (database_session_id, session.get("email_protocol", {}).get("value"), session.get("tls", {}).get("negotiated_version"), server.get("port"), client.get("address"), server.get("address"), network.get("first_timestamp"), analysis["deterministic_score"], analysis["deterministic_risk"], analysis["confidence"]["level"], json.dumps(analysis["confidence"]["reasons"]), analysis["deterministic_risk"]),
                )
                connection.execute("DELETE FROM findings WHERE session_id = ?", (database_session_id,))
                connection.executemany(
                    "INSERT INTO findings (session_id, \"check\", observed_value, risk_level, reference, rationale, confidence) VALUES (?, ?, ?, ?, ?, ?, ?)",
                    [(database_session_id, finding["check"], finding["observed_value"], finding["risk_level"], finding["reference"], finding["rationale"], finding["confidence"]) for finding in analysis["findings"]],
                )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Load analysis results into SQLite")
    parser.add_argument("json_files", nargs="+", help="parser JSON files")
    parser.add_argument("--database", default=str(DEFAULT_DATABASE))
    arguments = parser.parse_args()
    load_files(arguments.json_files, arguments.database)