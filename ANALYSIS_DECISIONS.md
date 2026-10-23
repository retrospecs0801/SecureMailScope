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
6. **`contributes_to_score` distinguishes ambiguity from observed weakness:** some findings describe the analyzer's uncertainty about a marginal context, not an actual weakness. A finding should only raise the deterministic floor when it reflects an observed cryptographic or deployment problem. The port-2525 case is the motivating example: a real SMTP session on a nonstandard port can legitimately be mapped to a different service or internal deployment, so `encryption_transition` reports a moderate rationale about the ambiguous mapping, but that ambiguity must not be allowed to floor every clean session. The fix is general, not port-specific: any future finding that is "context is ambiguous" rather than "a security weakness was observed" should set `contributes_to_score = false`.

## Explicit open hooks for future files

- `ai_score.py` must not use `deterministic_score` or `deterministic_risk` as its own label or predictive feature; that would be circular. It should use raw parser fields and may only escalate the deterministic floor.
- `anomaly_detection.py` should consume the raw session dict because timing, packet sizes, and reassembly behavior are not fully exposed as analysis findings.
- `risk_fusion.py` consumes `deterministic_score` / `deterministic_risk` as its floor and `confidence.level` when deciding whether to suppress an escalation. That fusion policy is not implemented here.
- `ai_score.py` / `risk_fusion.py` must respect `findings[].contributes_to_score` whenever they aggregate or average finding-level risk contributions themselves. If either file sums or averages risk by the raw finding list without filtering on `contributes_to_score`, it will silently reintroduce the same bug even if `deterministic_score` is corrected. The interface contract is that `deterministic_score` is already the filtered aggregate floor; direct per-finding aggregation must match the same exclusion rule.
- Dashboard consumers may show `findings[].rationale` and `.reference` verbatim to a SOC analyst.

## Known gaps / explicitly deferred

- STARTTLS and implicit-TLS port lists are hardcoded. Port 2525 and other nonstandard ports are reported as `moderate` ambiguity rather than inferred.
- OID and cipher lookup tables are intentionally small. Unmapped values become `data_unavailable` and include the raw value for later extension.
- This stage does not perform local trust-store validation, hostname validation, anomaly detection, or risk fusion. AI scoring is implemented separately by `ai_score.py`.

## Known Dataset Limitations

**Port variance is absent from the training dataset (as of `risk_scoring_v1.csv`, N=15).** Every scenario captured so far runs through the test harness on Docker-mapped port 2525, so `server_port` and `port_is_recognized_mail_port` have zero variance across the entire dataset — the model has never seen a session where `port_is_recognized_mail_port=True`. This means the trained model cannot have learned anything meaningful about this feature, and any apparent reliance on it (e.g. via SHAP/feature importance) in the trained model should be treated as noise, not signal. This is a deliberate scope decision for the prototype (fixing the harness's port handling was explicitly deferred), not an oversight — but it MUST be addressed before any production training run, by either varying the captured port across scenarios or, at minimum, synthetically varying this one feature in the feature vectors used for training (holding all other features constant) so the model has SOME signal on it before being trusted on real traffic that won't all arrive on port 2525.

## ai_score.py — Design Decisions & Interface

- Labels use the fixed mapping `{"low": 0, "moderate": 1, "high": 2, "critical": 3}` rather than alphabetical encoding, so class semantics remain stable when currently absent moderate/high examples are added later.
- `ai_score` is the probability-weighted sum of class midpoints: `sum(prob[c] * midpoint[c] for c in classes)`, with midpoints 12.5, 37.5, 62.5, and 87.5. These are the midpoints of the deterministic engine's 0-25, 25-50, 50-75, and 75-100 bands, so both scores use the same 0-100 scale.
- LOOCV is used instead of a train/test split because 15 rows make a conventional split unstable and uninformative. The per-row report is saved at `model/loocv_report_v1.csv` and is labeled as a small-sample sanity check, not a production generalization estimate.
- `risk_fusion.py` must treat the deterministic result as a floor: AI can only escalate that floor and must never lower it.
- `ai_confidence` is model-prediction confidence, meaning how certain the model is about its class prediction. It is distinct from `confidence.py`'s session evidence confidence, which measures how much of the session was observed or reassembled; fusion must consider them separately.

## ai_score.py — Design Decisions & Interface

- The label encoding order is fixed as `{"low": 0, "moderate": 1, "high": 2, "critical": 3}`. This is intentionally hardcoded rather than left to `sklearn.LabelEncoder`'s alphabetical ordering because the current dataset is intentionally low/critical-only and moderate/high are absent; future data additions should keep the same semantics without allowing alphabetical class ordering to silently change the numeric labels.
- `min_child_weight` was originally set to 2 as a conservative default, but at N=15 it empirically produced leaf-only, degenerate trees: a parameter probe showed 0 splits at weight 2 versus real splits at weight 1. It is therefore set to 1. This change only makes the model use the available features; LOOCV remains a small-sample sanity check, not a production generalization estimate.
- The AI score is a probability-weighted midpoint score: `sum(prob[class] * midpoint[class] for class in classes)` where the class midpoints are `low=12.5`, `moderate=37.5`, `high=62.5`, and `critical=87.5`. This is comparable to the deterministic engine's `0, 25, 50, 75, 100` bands because it sits on the same 0-100 scale even though it is a smooth, uncertainty-aware estimate instead of a banded floor.
- LOOCV was used instead of a train/test split because the current dataset contains only 15 rows. With that sample size, any held-out split would be unstable and not meaningful; the leave-one-out report is therefore the validation signal and it lives in `model/loocv_report_v1.csv`.
- `risk_fusion.py` has a strict contract: AI may only escalate the deterministic floor, never lower it. That rule is the actual boundary between the deterministic engine and the learned model, not just an implementation detail of this file.
- `ai_confidence` is model-prediction confidence: how certain the XGBoost model is about its own classification. It is not the same as `confidence.py`'s session evidence confidence, which measures how much of the session was actually observed or reassembled. These are two separate concepts and must remain distinct in fusion logic rather than being conflated into one number.