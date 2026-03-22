# Self-Learning AI Intrusion Detection System (IDS)

This project implements a full-featured, self-learning intrusion detection system using **Isolation Forest** AI. It captures live network traffic, extracts deep features, and provides a real-time monitoring dashboard with automated security alerts.

## 🎬 Project Showcase: Live Dashboard
The system features a professional-grade web interface for real-time security operations:

![AI IDS Dashboard Demo](assets/demo.webp)

- **Live Traffic Monitoring**: Real-time packet capture on active network interfaces (e.g., WiFi).
- **AI Deep-Dive**: Deep-packet inspection with per-packet anomaly scores.
- **Threat Filtering**: Instant isolation of security threats via the 'Suspicious only' toggle.
- **Visual Analytics**: Interactive Risk Index charts powered by Chart.js.
- **Export System**: Filtered CSV data export for forensics and reporting.

## 📽️ What's in the Video (~45 seconds)
If you're watching the demonstration video, here are the key highlights:
1. **Live Traffic Monitoring**: Real-time packet capture on the `WiFi` interface.
2. **AI Deep-Dive**: Clicking into individual packets to see the **Isolation Forest** anomaly scores.
3. **Threat Filtering**: Using the 'Suspicious only' toggle to isolate security alerts.
4. **Visual Analytics**: The **Real-time Risk Index** chart showing network health trends.

## Core Pipeline
- **Phase 1: Capture**: IPv4 packet sniffing from live traffic or `.pcap` files.
- **Phase 2: Features**: Temporal and protocol feature extraction (16 enriched features).
- **Phase 3: Training**: Self-learning unsupervised anomaly detection.
- **Phase 4: Inference**: Real-time prediction with quantile-based risk calibration.
- **Phase 5: Dashboard**: High-fidelity Flask web UI with glassmorphism design.
- **Phase 6: Alerts**: Multi-channel notifications (Log, Sound, SMTP Email).

## Project Layout

```text
self-learning-ids/
├─ app.py                # Main Entry Point
├─ requirements.txt
├─ saved_model.pkl       # Trained AI Model
├─ README.md
├─ model.py              # Standalone Training Script
├─ realtime.py           # Standalone Detection Script
├─ evaluate_model.py     # Evaluation Report Generator
├─ generate_dummy_model.py # Model Architecture Generator
├─ ids/                  # Core Engine
│  ├─ capture.py
│  ├─ features.py
│  ├─ model.py
│  ├─ realtime.py
│  └─ dashboard.py       # Metrics & Monitoring logic
├─ web/                  # Web Interface Layer
│  └─ routes.py
├─ templates/            # UI Components
├─ data/                 # Sample PCAPs & Datasets
├─ logs/                 # Security Alerts & System Logs
└─ tests/                # Full 25-test Validation Suite
```

## Setup & Usage
Please refer to the source code and individual script headers for detailed CLI arguments. Most operations can be performed via the main `app.py` entry point.
