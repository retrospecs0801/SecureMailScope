"""Read-only SecureMailScope dashboard. Run with: streamlit run dashboard.py"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pandas as pd
import streamlit as st

RISK_ORDER = {"critical": 4, "high": 3, "moderate": 2, "low": 1}
RISK_COLORS = {"low": "#198754", "moderate": "#d39e00", "high": "#e76f00", "critical": "#c1121f"}


def risk_color(value: object) -> str:
    return RISK_COLORS.get(str(value), "#6c757d")


def style_risk_table(frame: pd.DataFrame) -> object:
    columns = [column for column in ("deterministic_risk", "final_risk", "risk_level") if column in frame]
    return frame.style.map(lambda value: f"color: {risk_color(value)}; font-weight: 600", subset=columns)


DATABASE_PATH = Path(__file__).resolve().with_name("sessions.db")


def load_data(database: Path = DATABASE_PATH) -> tuple[pd.DataFrame, pd.DataFrame]:
    empty_sessions = pd.DataFrame()
    empty_findings = pd.DataFrame()
    if not database.exists():
        return empty_sessions, empty_findings

    with sqlite3.connect(database) as connection:
        tables = {
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            )
        }
        if not {"sessions", "findings"}.issubset(tables):
            return empty_sessions, empty_findings
        sessions = pd.read_sql_query("SELECT *, COALESCE(final_risk, deterministic_risk) AS display_risk FROM sessions", connection)
        findings = pd.read_sql_query('SELECT id, session_id, "check", observed_value, risk_level, reference, rationale, confidence FROM findings', connection)
    if not sessions.empty:
        sessions["risk_sort"] = sessions["display_risk"].map(RISK_ORDER).fillna(0)
        sessions = sessions.sort_values(["risk_sort", "session_id"], ascending=[False, True])
    return sessions, findings


st.set_page_config(page_title="SecureMailScope", layout="wide")
st.title("SecureMailScope")
sessions, findings = load_data()
if sessions.empty:
    st.info("No analyzed sessions are available yet.")
    st.code(
        "python load_analysis_to_db.py capture\\postfix_tls12_expired_cert.json",
        language="powershell",
    )
    st.caption(f"Expected database: {DATABASE_PATH}")
    st.stop()

metrics = st.columns(5)
metrics[0].metric("Total sessions", len(sessions))
for column, label in zip(metrics[1:], ("Critical", "High", "Moderate", "Low")):
    column.metric(label, int((sessions["display_risk"] == label.lower()).sum()))

selected_risks = st.multiselect("Risk levels", ["critical", "high", "moderate", "low"], default=["critical", "high", "moderate", "low"])
filtered = sessions[sessions["display_risk"].isin(selected_risks)]
display_columns = ["session_id", "protocol", "tls_version", "deterministic_risk", "confidence_level", "display_risk"]
display = filtered[display_columns].rename(columns={"display_risk": "final_risk"})
st.dataframe(style_risk_table(display), width="stretch", hide_index=True)

if not filtered.empty:
    selected_id = st.selectbox("Session details", filtered["session_id"].tolist())
    selected = sessions[sessions["session_id"] == selected_id].iloc[0]
    st.subheader(f"Session {selected_id}")
    st.write({"protocol": selected.get("protocol"), "server_port": selected.get("server_port"), "client_ip": selected.get("client_ip"), "server_ip": selected.get("server_ip"), "timestamp": selected.get("timestamp")})
    st.write(f"Confidence: **{selected.get('confidence_level')}**")
    for reason in json.loads(selected.get("confidence_reasons") or "[]"):
        st.write(f"- {reason}")
    session_findings = findings[findings["session_id"] == selected_id]
    st.dataframe(style_risk_table(session_findings[["check", "observed_value", "risk_level", "reference", "rationale"]]), width="stretch", hide_index=True)