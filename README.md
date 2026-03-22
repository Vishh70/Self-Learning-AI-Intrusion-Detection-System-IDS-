# Self-Learning AI Intrusion Detection System (IDS)

This project implements the full seven-phase self-learning intrusion detection system:

- Phase 1: capture IPv4 packets from live traffic or a `.pcap` file
- Phase 2: extract structured features and store them as CSV for later ML training
- Phase 3: train an Isolation Forest model and save anomaly predictions
- Phase 4: run real-time anomaly detection from live traffic or `.pcap` replay
- Phase 5: visualize recent model decisions in a Flask dashboard
- Phase 6: trigger alert logging, sound, and optional email notifications
- Phase 7: final integration, validation, demo preparation, and viva/report guidance

## Project Layout

```text
self-learning-ids/
├─ app.py
├─ requirements.txt
├─ README.md
├─ PHASE7_FINAL_GUIDE.md
├─ evaluate_model.py
├─ final_check.py
├─ model.py
├─ realtime.py
├─ data/
│  ├─ raw/
│  └─ processed/
├─ logs/
├─ ids/
│  ├─ __init__.py
│  ├─ config.py
│  ├─ capture.py
│  ├─ alerts.py
│  ├─ dashboard.py
│  ├─ evaluation.py
│  ├─ features.py
│  ├─ health.py
│  ├─ model.py
│  ├─ realtime.py
│  ├─ storage.py
│  └─ utils.py
├─ web/
│  ├─ __init__.py
│  └─ routes.py
└─ tests/
   ├─ test_alerts.py
   ├─ test_features.py
   ├─ test_capture_smoke.py
   ├─ test_model.py
   ├─ test_dashboard.py
   ├─ test_realtime.py
   ├─ test_evaluation.py
   ├─ test_health.py
   ├─ test_web_routes.py
   └─ test_integration_pipeline.py
```

## Setup

### 1. Create a virtual environment

```powershell
python -m venv .venv
```

### 2. Activate the virtual environment

```powershell
.venv\Scripts\Activate.ps1
```

### 3. Install dependencies

```powershell
pip install -r requirements.txt
```

Optional runtime configuration:

- Copy `.env.example` to your environment setup and adjust the alert settings.
- Use `run_ids.ps1` for repeatable local startup commands.

## Run Packet Capture

Default mode is `.pcap`, which is safer for development and demos.

### Replay from a sample `.pcap`

```powershell
python app.py --mode pcap --pcap data/raw/sample.pcap --max-packets 10
```

### Live sniffing

```powershell
python app.py --mode live --iface Wi-Fi --max-packets 100
```

Notes:

- On Windows, live sniffing may require Administrator privileges.
- Npcap may be required for Scapy live capture support.
- If live capture fails, use `.pcap` mode first.

## Run The Flask App

```powershell
python app.py --serve --mode pcap --pcap data/raw/sample.pcap --model-path saved_model.pkl
```

Then open `http://127.0.0.1:5000/`.

The dashboard starts a background realtime monitor and renders the last 20 predictions.
The page also polls `/api/events` every few seconds so the table updates without a manual refresh.
It also exposes `/api/health` for runtime status and lets you inspect packet details by clicking a row.

## Run Tests

```powershell
.\venv\Scripts\python.exe -m pytest
```

If `pytest` is missing from the virtual environment, rerun:

```powershell
.\venv\Scripts\pip.exe install -r requirements.txt
```

## Train The Phase 3 Model

Train from the Phase 2 feature dataset:

```powershell
python model.py
```

Or use the main entrypoint:

```powershell
python app.py --train-model --features-csv data/processed/packet_features.csv
```

Output files:

- Predictions: `data/processed/model_results.csv`
- Saved model: `saved_model.pkl`

## Evaluate The Latest Model Results

```powershell
python evaluate_model.py
```

Or:

```powershell
python app.py --evaluate-model --results-csv data/processed/model_results.csv
```

This writes `data/processed/evaluation_summary.json`.

## Run Phase 4 Real-Time Detection

Use the trained model with live traffic:

```powershell
python app.py --realtime --mode live --iface Wi-Fi --model-path saved_model.pkl
```

For development and demos, replay the sample `.pcap` through the same inference path:

```powershell
python app.py --realtime --mode pcap --pcap data/raw/sample.pcap --model-path saved_model.pkl
```

You can also use the dedicated runner:

```powershell
python realtime.py
```

Output file:

- Real-time predictions: `data/processed/realtime_predictions.csv`

## Phase 5 Dashboard

The dashboard shows:

- recent packet decisions
- suspicious vs normal counts
- realtime monitor status
- anomaly score, protocol, and endpoints for each packet

## Phase 6 Alerts

Suspicious packets now trigger:

- log file entries in `logs/alerts.log`
- local sound alerts when enabled
- email alerts when SMTP settings are configured

Environment variables:

- `IDS_SOUND_ALERTS_ENABLED=true|false`
- `IDS_EMAIL_ALERTS_ENABLED=true|false`
- `IDS_ALERT_COOLDOWN_SECONDS=30`
- `IDS_SMTP_HOST=smtp.gmail.com`
- `IDS_SMTP_PORT=587`
- `IDS_SMTP_SENDER=your_email@gmail.com`
- `IDS_SMTP_RECEIVER=receiver_email@gmail.com`
- `IDS_SMTP_PASSWORD=your_app_password`

Production hardening added:

- rotating alert logs
- per-source and destination cooldown for sound and email notifications
- optional runtime-only configuration via environment variables

## Output Files

- Raw packet summaries: `data/processed/raw_packets.csv`
- Extracted features: `data/processed/packet_features.csv`
- Batch model predictions: `data/processed/model_results.csv`
- Real-time predictions: `data/processed/realtime_predictions.csv`
- Alert log: `logs/alerts.log`
- Final validation artifacts: `data/processed/final_check/`

## Phase 7 Final Check

Run the final integration check:

```powershell
.\venv\Scripts\python.exe final_check.py
```

This validates:

- sample packet capture and feature extraction
- model training
- realtime inference
- dashboard routes

See [PHASE7_FINAL_GUIDE.md](PHASE7_FINAL_GUIDE.md) for the final demo flow, viva answers, and report outline.

## Productionization Pass

Additional local-run improvements now included:

- `pytest.ini` for consistent test discovery
- `.env.example` for alert and dashboard settings
- `run_ids.ps1` for capture, training, realtime, dashboard, and final-check commands
- dashboard filtering for suspicious traffic only
- download routes for alerts and CSV outputs
- anomaly rate summary and quick visual traffic bars
- clickable packet detail panel in the dashboard
- runtime health check via `python app.py --health-check`
- model evaluation summary via `evaluate_model.py`

## Current Scope

Included:

- packet capture
- packet summary printing
- feature extraction
- Isolation Forest training
- real-time anomaly detection
- Flask dashboard UI
- alert logging, sound, and optional email
- CSV persistence
- Flask health endpoint

Not included yet:

- deployment pipeline
