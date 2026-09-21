"""Confidence calculation for passive parser sessions."""

from __future__ import annotations


_LEVELS = {"low": 1, "medium": 2, "high": 3}
_LABELS = {1: "low", 2: "medium", 3: "high"}
_SCORES = {"low": 0.3, "medium": 0.6, "high": 0.9}


def compute_session_confidence(session: dict) -> dict:
    """Return deterministic confidence by applying the four session rules.

    First, the least confident present evidence block establishes the base level.
    Next, any non-complete TCP reassembly downgrades it once, and an RST combined
    with a non-observed handshake downgrades it once more.  Downgrades are clamped
    at low, and the returned score is only the fixed convenience mapping high=.9,
    medium=.6, and low=.3.
    """
    evidence_blocks = ("email_protocol", "encryption", "certificate_availability")
    evidence_confidences = {
        name: session.get(name, {}).get("confidence")
        for name in evidence_blocks
        if session.get(name, {}).get("confidence") in _LEVELS
    }
    base_value = min((_LEVELS[value] for value in evidence_confidences.values()), default=3)
    level_value = base_value
    reasons: list[str] = []

    tcp = session.get("tcp", {})
    reassembly_status = {
        direction: tcp.get(direction, {}).get("status", "unknown")
        for direction in ("client_to_server", "server_to_client")
    }
    for direction, status in reassembly_status.items():
        if status != "complete":
            level_value = max(1, level_value - 1)
            reasons.append(f"{direction} reassembly status is '{status}'")

    rst_seen = tcp.get("rst_seen", False) is True
    handshake_status = session.get("tls", {}).get("handshake_completion_status", "unknown")
    if rst_seen and handshake_status != "observed":
        level_value = max(1, level_value - 1)
        reasons.append(
            f"rst_seen=true while handshake_completion_status='{handshake_status}'"
        )

    level = _LABELS[level_value]
    if not reasons:
        reasons.append("no confidence downgrades; available evidence is high confidence and reassembly is complete")
    return {
        "level": level,
        "score": _SCORES[level],
        "reasons": reasons,
        "inputs": {
            "evidence_block_confidences": evidence_confidences,
            "reassembly_status": reassembly_status,
            "rst_seen": rst_seen,
            "handshake_completion_status": handshake_status,
        },
    }