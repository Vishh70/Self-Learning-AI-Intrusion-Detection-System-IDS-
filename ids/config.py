from __future__ import annotations

import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
RAW_DATA_DIR = DATA_DIR / "raw"
PROCESSED_DATA_DIR = DATA_DIR / "processed"
LOGS_DIR = BASE_DIR / "logs"

CAPTURE_MODE = "pcap"
PCAP_PATH = RAW_DATA_DIR / "sample.pcap"
INTERFACE = None
MAX_PACKETS = 25

RAW_OUTPUT_CSV = PROCESSED_DATA_DIR / "raw_packets.csv"
PROCESSED_FEATURES_CSV = PROCESSED_DATA_DIR / "packet_features.csv"
MODEL_OUTPUT_CSV = PROCESSED_DATA_DIR / "model_results.csv"
REALTIME_OUTPUT_CSV = PROCESSED_DATA_DIR / "realtime_predictions.csv"
SAVED_MODEL_PATH = BASE_DIR / "saved_model.pkl"
ALERTS_LOG_PATH = LOGS_DIR / "alerts.log"
EVALUATION_SUMMARY_JSON = PROCESSED_DATA_DIR / "evaluation_summary.json"
RAW_OUTPUT_DOWNLOAD_NAME = "raw_packets.csv"
FEATURE_OUTPUT_DOWNLOAD_NAME = "packet_features.csv"
MODEL_OUTPUT_DOWNLOAD_NAME = "model_results.csv"
REALTIME_OUTPUT_DOWNLOAD_NAME = "realtime_predictions.csv"

FLASK_HOST = "127.0.0.1"
FLASK_PORT = 5001
FLASK_DEBUG = False


def _get_bool_env(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


SOUND_ALERTS_ENABLED = _get_bool_env("IDS_SOUND_ALERTS_ENABLED", True)
EMAIL_ALERTS_ENABLED = _get_bool_env("IDS_EMAIL_ALERTS_ENABLED", False)
ALERT_COOLDOWN_SECONDS = int(os.getenv("IDS_ALERT_COOLDOWN_SECONDS", "30"))
SMTP_HOST = os.getenv("IDS_SMTP_HOST", "smtp.gmail.com")
SMTP_PORT = int(os.getenv("IDS_SMTP_PORT", "587"))
SMTP_SENDER = os.getenv("IDS_SMTP_SENDER", "")
SMTP_RECEIVER = os.getenv("IDS_SMTP_RECEIVER", "")
SMTP_PASSWORD = os.getenv("IDS_SMTP_PASSWORD", "")
ALERT_LOG_MAX_BYTES = int(os.getenv("IDS_ALERT_LOG_MAX_BYTES", "262144"))
ALERT_LOG_BACKUP_COUNT = int(os.getenv("IDS_ALERT_LOG_BACKUP_COUNT", "3"))
DASHBOARD_DEFAULT_LIMIT = int(os.getenv("IDS_DASHBOARD_DEFAULT_LIMIT", "20"))
DASHBOARD_MAX_LIMIT = int(os.getenv("IDS_DASHBOARD_MAX_LIMIT", "100"))

# Auto-train settings (self-learning)
AUTO_TRAIN_ENABLED = _get_bool_env("IDS_AUTO_TRAIN_ENABLED", False)
AUTO_TRAIN_INTERVAL_SECONDS = int(os.getenv("IDS_AUTO_TRAIN_INTERVAL_SECONDS", "300"))
AUTO_TRAIN_MIN_NEW_ROWS = int(os.getenv("IDS_AUTO_TRAIN_MIN_NEW_ROWS", "200"))
AUTO_TRAIN_MIN_TOTAL_ROWS = int(os.getenv("IDS_AUTO_TRAIN_MIN_TOTAL_ROWS", "500"))
