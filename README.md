# SecureMailScope

SecureMailScope is a prototype for passively analyzing packet captures of
email traffic and assessing the security of the associated TLS sessions. It
focuses on SMTP, IMAP, and POP3 traffic, including STARTTLS and implicit TLS.
It parses protocol and certificate evidence into structured session data,
applies deterministic security checks, and provides a Streamlit dashboard for
reviewing stored analyses.

The repository also contains an experimental machine-learning risk scorer. It
is a separate prototype, not yet part of the database-loading or dashboard
workflow; see [AI risk scoring](#ai-risk-scoring-prototype) for its current
scope and limitations.

## How it works

```text
PCAP / PCAPNG
    |
    v
TCP reassembly and email/TLS parsing  (analyzer/)
    |
    v
Structured session JSON
    |
    +--> Deterministic security findings and risk score
    |        |
    |        +--> SQLite database --> Streamlit dashboard
    |
    +--> Experimental AI risk score (ai_score.py; separate workflow)
```

The parser extracts observable TLS and certificate evidence from packet
captures. The deterministic analyzer evaluates findings such as TLS version,
cipher suite, key exchange, and certificate properties. It also reports
confidence in the available session evidence. The dashboard reads analysis
records from `sessions.db`; it does not currently calculate or display scores
from the AI model.

## Run locally

### Requirements

- Python with the packages in `requirements.txt`
- Docker with Docker Compose, for generating the local mail/TLS test traffic
- `tshark`, available on `PATH`, for capturing that traffic

Install the Python dependencies in your environment:

```powershell
python -m pip install -r requirements.txt
```

To parse a capture you already have and save deterministic analysis to SQLite:

```powershell
python analyzer/parser.py path\to\capture.pcapng --output capture\session.json
python load_analysis_to_db.py capture\session.json
streamlit run dashboard.py
```

The dashboard opens in a browser. `load_analysis_to_db.py` stores deterministic
findings and risk in the local `sessions.db` file.

### Generate a local test capture

The included Postfix test harness creates local SMTP/TLS sessions for the
labeled scenarios. Its certificate keys, PCAPs, and parsed capture JSON are
generated locally and are intentionally not committed to the repository.
From the project root, run:

```powershell
python scripts/run_tls_scenario.py tls12_strong
```

To regenerate the full labeled training dataset, run:

```powershell
python build_training_dataset.py
```

The dataset builder uses the labeled scenarios in
[`scripts/run_tls_scenario.py`](scripts/run_tls_scenario.py). For each scenario,
it reuses a parsed JSON fixture in `capture/` when available, or generates the
fixture using Docker Compose, Postfix, and `tshark`. It extracts the model
features from each parsed session and writes
[`datasets/risk_scoring_v1.csv`](datasets/risk_scoring_v1.csv).

## AI risk scoring prototype

### Model

The prototype uses **XGBoost**, trained as a four-class gradient-boosted tree
classifier. Training is implemented in
[`train_ai_risk_model.py`](train_ai_risk_model.py); runtime scoring is
implemented in [`ai_score.py`](ai_score.py).

The model is trained with the `multi:softprob` objective, so it returns a
probability for each risk class: `low`, `moderate`, `high`, and `critical`.
Training uses 25 boosting rounds, a maximum tree depth of 2, learning rate
(`eta`) 0.2, and `min_child_weight` 1. Three categorical inputs (key-exchange
mechanism, certificate public-key algorithm, and encryption mode) are mapped
to numeric values; unknown categories use a dedicated fallback value.

The model consumes 17 features extracted from raw parsed session fields. They
describe:

- TLS version and whether the cipher is AEAD or a legacy weak cipher
- Key-exchange mechanism and forward secrecy
- Certificate availability, validity dates, self-signing, chain/issuer
  verification, public-key size and algorithm, and signature strength
- Encryption mode and the server port

Feature extraction is intentionally separate from deterministic findings: the
AI scorer does not use the deterministic score or risk label as model inputs.

### Dataset and training

The checked-in dataset is
[`datasets/risk_scoring_v1.csv`](datasets/risk_scoring_v1.csv). It currently
contains **15 labeled scenario rows: 7 `low` and 8 `critical`**. The labels
come from the controlled scenarios in `scripts/run_tls_scenario.py`, which
exercise selected TLS and certificate configurations. The training set is
therefore a small, synthetic test-harness dataset, not a sample of real-world
mail traffic.

To rebuild the dataset and train the model:

```powershell
python build_training_dataset.py
python train_ai_risk_model.py
```

Training evaluates tree depths 2 and 3 using leave-one-out cross-validation
(LOOCV), writes the per-row results to
[`model/loocv_report_v1.csv`](model/loocv_report_v1.csv), and then fits the
saved model on the full dataset. The current final model uses depth 2. Model
artifacts are stored in `model/`:

- `ai_risk_model.json` — trained XGBoost model
- `label_mapping.json` and `categorical_mappings.json` — class and feature
  encodings required for inference
- `feature_importance.csv` — feature importance from the full-data fit
- `loocv_report_v1.csv` — per-scenario cross-validation results

### How classification and scoring work

For a parsed session, `score_session(session)` extracts the same 17 features,
applies the saved category mappings, and asks XGBoost for the four class
probabilities. The predicted risk label is the class with the highest
probability. The returned `ai_score` is a probability-weighted average of
class midpoints on a 0–100 scale (`12.5`, `37.5`, `62.5`, and `87.5` for low
through critical). `ai_confidence` is the highest class probability; it is
model confidence, not the separate evidence/reassembly confidence produced by
the deterministic analyzer.

Example:

```python
from ai_score import score_session

result = score_session(parsed_session)
print(result["ai_risk_label"], result["ai_score"], result["class_probabilities"])
```

### Limitations and future scope

- **Only low and critical have training examples.** Although the classifier
  exposes four class probabilities, there are currently no `moderate` or
  `high` examples to teach those classes. Predictions and scores in those
  middle bands are not validated and should not be treated as reliable.
- **The dataset is very small.** LOOCV is included as a small-sample sanity
  check, not as evidence of production performance or generalization.
- **The captures are controlled scenarios.** They do not represent the
  diversity of mail servers, deployments, traffic, or certificate
  configurations seen in practice.
- **Port features do not vary in the current dataset.** The test harness
  captures on a Docker-mapped port, so the model cannot learn a useful
  relationship between the port features and risk yet.
- **AI scoring is not integrated into the main analysis workflow.** Loading
  parsed JSON into SQLite and viewing it in the dashboard currently uses the
  deterministic analyzer; AI, anomaly detection, and score fusion are future
  integration work.

Next steps include adding labeled moderate- and high-risk scenarios, collecting
diverse and carefully reviewed traffic examples, varying or otherwise
validating port-related features, evaluating on held-out scenarios that are
independent of training, and integrating AI predictions without allowing them
to reduce deterministic risk findings.

## Project layout

```text
analyzer/       Packet parsing and deterministic session analysis
scripts/        Local Postfix/TLS scenario and fixture-generation tools
tests/          Automated tests
datasets/       Labeled AI training dataset
model/          Trained model, feature mappings, and evaluation artifacts
features.py     Shared AI feature extraction
ai_score.py     AI inference and probability-weighted score
dashboard.py    Streamlit dashboard for SQLite analysis results
```

Run the automated tests from the project root with:

```powershell
python -m pytest tests
```
