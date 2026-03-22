# 🛡️ Self-Learning AI Intrusion Detection System (IDS)

[![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)](https://www.python.org/)
[![AI-Model](https://img.shields.io/badge/AI-IsolationForest-orange.svg)](https://scikit-learn.org/)
[![Flask](https://img.shields.io/badge/Web-Flask-green.svg)](https://flask.palletsprojects.com/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A high-performance, **Self-Learning Intrusion Detection System** built from the ground up using Network Security principles and Advanced Machine Learning. This system doesn't just block known threats—it **learns** your network's normal behavior and detects novel anomalies in real-time.

---

## 🎬 Project Showcase: Live Dashboard
Experience the system's real-time analysis through our high-fidelity dashboard:

![AI IDS Dashboard Demo](assets/demo.webp)

**Key Highlights (~45 seconds):**
1. **Live Traffic Monitoring**: Captured directly from the system's `WiFi` adapter.
2. **Deep-Packet AI Analysis**: Real-time scoring using our custom **Isolation Forest** implementation.
3. **Interactive Threat Triage**: Selecting packets to reveal underlying feature distributions.
4. **Visual Risk Index**: Dynamic `Chart.js` integration showing network health trends.

---

## 🚀 Core Features

- **🧠 Self-Learning AI Engine**: Uses unsupervised **Isolation Forest** to detect threats without predefined signatures.
- **⚡ Real-Time Pipeline**: Zero-latency processing of 16 network features per packet.
- **🛡️ Multi-Channel Alerting**: Instant notifications via standard Logs, Desktop Sound, and SMTP Email.
- **📊 3D Forensics**: Interactive dashboard with protocol filtering (TCP/UDP/ICMP) and source-based triage.
- **⚖️ Dynamic Calibration**: Multi-point quantile mapping ensures consistent 1-100% Risk scaling.
- **✅ Rock-Solid Validation**: Includes a comprehensive **25-test suite** covering every module from capture to inference.

---

## 🛠️ Technology Stack

| Layer | Technologies |
|-------|--------------|
| **Core Engine** | Python 3.10+, Scapy (Packet Sniffing/Parsing) |
| **Machine Learning** | Scikit-learn (Isolation Forest), Pandas, NumPy |
| **Web Infrastructure** | Flask, Werkzeug, Jinja2 |
| **Frontend/UI** | Vanilla CSS (Glassmorphism), Chart.js, Lucide Icons |
| **Testing/QA** | Pytest, Shutil, OS-level handle management |

---

## 🧩 System Architecture

```mermaid
graph TD
    A[Live Traffic / PCAP] --> B[Scapy Sniffer]
    B --> C[Feature Extractor]
    C --> D[16-Feature Vector]
    D --> E[Inference Engine]
    E --> F[Isolation Forest Model]
    F --> G[Anomaly Prediction]
    G --> H[Risk Calibration]
    H --> I[Alert Manager]
    H --> J[Live Dashboard]
    I --> K[Log File]
    I --> L[Sound Alarm]
    I --> M[SMTP Email]
```

---

## 📁 Project Structure

```text
self-learning-ids/
├─ app.py                # Main System Entry Point
├─ saved_model.pkl       # Trained AI Model
├─ ids/                  # Core Engine
├─ web/                  # API and Routing Layer
├─ templates/            # UI Components
├─ tests/                # Full 25-test Validation Suite
└─ data/                 # Sample Datasets & PCAPs
```

---

## ⚡ Execution Guide: How to Run This Project

Run these commands in **PowerShell** from the project root.

### 1️⃣ Capture + Build Features (Phase 2)
Capture live network traffic and extract features for training.
```powershell
.\venv\Scripts\python.exe app.py --mode live --iface WiFi --max-packets 500
```

### 2️⃣ Train Model (Phase 3)
Train the AI "Brain" from the captured feature dataset.
```powershell
.\venv\Scripts\python.exe app.py --train-model --features-csv data\processed\packet_features.csv
```

### 3️⃣ Run Real-Time CLI (No Dashboard)
Run the AI inference engine directly in your terminal.
```powershell
.\venv\Scripts\python.exe app.py --realtime --mode live --iface WiFi --model-path saved_model.pkl
```

### 4️⃣ Run AI IDS Dashboard (Web)
Launch the professional monitoring interface.
```powershell
.\venv\Scripts\python.exe app.py --serve --mode live --iface WiFi --model-path saved_model.pkl
```

---

## ⏹️ Stop Server & Manage Processes

### Stop the Current Command:
If you started a process in the terminal, stop it with:
- **`Ctrl + C`**

### "Nuclear" Stop (Kill All Background Background Processes):
If the server is stuck or running in the background, run this in PowerShell:
```powershell
Get-Process python | Where-Object { $_.Path -like "*Self-Learning AI Intrusion Detection System (IDS)*" } | Stop-Process -Force
```
*Note: If nothing is listed, no processes from this project are currently running.*

---

## ✅ Validation Summary
Rigorously tested to ensure 100% accuracy and stability:
```powershell
.\venv\Scripts\python.exe -m pytest
```
**Current Status:** `25 Passed | 0 Failed`

---

## 📝 License
Distributed under the MIT License. Developed with ❤️ by [Vishnu (Vishh70)](https://github.com/Vishh70) & [Atharva (Atharva-cell-web)](https://github.com/Atharva-cell-web).
