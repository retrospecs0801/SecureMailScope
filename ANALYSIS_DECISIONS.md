# analysis.py - Design Decisions & Downstream Interface

## What this file guarantees to callers

- Every parser schema version 1.0 session produces one `analyze_session()` result with `session_id`, `confidence`, `findings`, `deterministic_score`, `deterministic_risk`, and `warnings`.
- `deterministic_score` is always an integer in `{0, 25, 50, 75, 100}`. Downstream code must not treat it as a continuous scale.
- The finding vocabulary is versioned as: `tls_version`, `cipher_suite`, `key_exchange`, `certificate_validity[index]`, `certificate_chain`, `public_key_strength[index]`, `signature_algorithm[index]`, and `encryption_transition`.
- Confidence is attached to the session and every finding. Finding confidence inherits the session confidence; there are no check-specific overrides.
- TLS 1.3 sessions can have fewer certificate findings because certificates are encrypted. Missing certificate findings mean not observable, not insecure.
- `data_unavailable` is represented by a low-risk finding with a rationale and `reference` of `N/A`; it does not contribute to the score.

## Design decisions and why (read this before changing scoring logic)

1. **Max-severity floor:** averaging could dilute one critical weakness with many low findings. The maximum finding severity establishes the floor. Future `ai_score.py` may only escalate this floor; it must never lower it.
2. **Key exchange owns forward secrecy:** forward secrecy is folded into `key_exchange` so the same underlying property is not counted twice.
3. **Unavailable data is not scored:** passive-analysis limitations are neither secure nor risky. They remain explicitly unknown.
4. **Certificate checks are skipped when unavailable:** treating unavailable certificates as low would falsely turn lack of observation into a security conclusion.
5. **Three-high escalation:** three or more independent high-or-critical check families indicate compounding weaknesses even when no single weakness is critical, so the max floor rises one tier.

## Explicit open hooks for future files

- `ai_score.py` must not use `deterministic_score` or `deterministic_risk` as its own label or predictive feature; that would be circular. It should use raw parser fields and may only escalate the deterministic floor.
- `anomaly_detection.py` should consume the raw session dict because timing, packet sizes, and reassembly behavior are not fully exposed as analysis findings.
- `risk_fusion.py` consumes `deterministic_score` / `deterministic_risk` as its floor and `confidence.level` when deciding whether to suppress an escalation. That fusion policy is not implemented here.
- Dashboard consumers may show `findings[].rationale` and `.reference` verbatim to a SOC analyst.

## Known gaps / explicitly deferred

- STARTTLS and implicit-TLS port lists are hardcoded. Port 2525 and other nonstandard ports are reported as `moderate` ambiguity rather than inferred.
- OID and cipher lookup tables are intentionally small. Unmapped values become `data_unavailable` and include the raw value for later extension.
- This stage does not perform local trust-store validation, hostname validation, AI scoring, anomaly detection, or risk fusion.