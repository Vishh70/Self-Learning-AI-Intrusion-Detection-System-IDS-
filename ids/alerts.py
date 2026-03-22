from __future__ import annotations

import smtplib
import sys
import time
from datetime import datetime
from email.mime.text import MIMEText
from logging import Formatter, Logger, getLogger
from logging.handlers import RotatingFileHandler

from ids.config import (
    ALERTS_LOG_PATH,
    ALERT_COOLDOWN_SECONDS,
    ALERT_LOG_BACKUP_COUNT,
    ALERT_LOG_MAX_BYTES,
    EMAIL_ALERTS_ENABLED,
    LOGS_DIR,
    SMTP_HOST,
    SMTP_PASSWORD,
    SMTP_PORT,
    SMTP_RECEIVER,
    SMTP_SENDER,
    SOUND_ALERTS_ENABLED,
)

_last_sound_alert = 0.0
_last_email_alert = 0.0
_last_sound_by_key: dict[str, float] = {}
_last_email_by_key: dict[str, float] = {}
_alert_logger: Logger | None = None


def _build_alert_key(prediction: dict) -> str:
    return "|".join(
        [
            str(prediction.get("src_ip", "")),
            str(prediction.get("dst_ip", "")),
            str(prediction.get("protocol_name", "")),
        ]
    )


def _get_alert_logger() -> Logger:
    global _alert_logger
    if _alert_logger is not None:
        return _alert_logger

    LOGS_DIR.mkdir(parents=True, exist_ok=True)
    logger = getLogger("ids.alerts")
    logger.setLevel("INFO")
    logger.propagate = False

    if not logger.handlers:
        handler = RotatingFileHandler(
            ALERTS_LOG_PATH,
            maxBytes=ALERT_LOG_MAX_BYTES,
            backupCount=ALERT_LOG_BACKUP_COUNT,
            encoding="utf-8",
        )
        handler.setFormatter(Formatter("%(asctime)s - %(message)s"))
        logger.addHandler(handler)

    _alert_logger = logger
    return logger


def build_alert_message(prediction: dict) -> str:
    timestamp = prediction.get("timestamp", "unknown-time")
    src_ip = prediction.get("src_ip", "unknown-src")
    dst_ip = prediction.get("dst_ip", "unknown-dst")
    protocol = prediction.get("protocol_name", "UNKNOWN")
    score = prediction.get("anomaly_score", 0.0)
    risk = prediction.get("risk_score", 0.0)
    return (
        f"ALERT {timestamp} src={src_ip} dst={dst_ip} "
        f"proto={protocol} score={score:.6f} risk={risk:.1f}%"
    )


def log_alert(message: str, path: str | None = None) -> str:
    timestamp = datetime.now().isoformat(timespec="seconds")
    if path is None:
        _get_alert_logger().info(message)
        return f"{timestamp} - {message}"

    LOGS_DIR.mkdir(parents=True, exist_ok=True)
    with open(path, "a", encoding="utf-8") as handle:
        handle.write(f"{timestamp} - {message}\n")
    return f"{timestamp} - {message}"


def sound_alert(prediction: dict, force: bool = False) -> bool:
    global _last_sound_alert

    if not SOUND_ALERTS_ENABLED:
        return False

    now = time.monotonic()
    alert_key = _build_alert_key(prediction)
    if not force and (
        now - _last_sound_alert < ALERT_COOLDOWN_SECONDS
        or now - _last_sound_by_key.get(alert_key, 0.0) < ALERT_COOLDOWN_SECONDS
    ):
        return False

    try:
        if sys.platform.startswith("win"):
            import winsound

            winsound.Beep(1000, 500)
        else:
            print("[ALERT] sound notification unavailable on this platform")
    except Exception:
        print("[ALERT] sound notification failed")
        return False

    _last_sound_alert = now
    _last_sound_by_key[alert_key] = now
    return True


def send_email_alert(message: str, prediction: dict, force: bool = False) -> bool:
    global _last_email_alert

    if not EMAIL_ALERTS_ENABLED:
        return False
    if not SMTP_SENDER or not SMTP_RECEIVER or not SMTP_PASSWORD:
        return False

    now = time.monotonic()
    alert_key = _build_alert_key(prediction)
    if not force and (
        now - _last_email_alert < ALERT_COOLDOWN_SECONDS
        or now - _last_email_by_key.get(alert_key, 0.0) < ALERT_COOLDOWN_SECONDS
    ):
        return False

    msg = MIMEText(message)
    msg["Subject"] = "AI IDS Intrusion Alert"
    msg["From"] = SMTP_SENDER
    msg["To"] = SMTP_RECEIVER

    with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=10) as server:
        server.starttls()
        server.login(SMTP_SENDER, SMTP_PASSWORD)
        server.sendmail(SMTP_SENDER, [SMTP_RECEIVER], msg.as_string())

    _last_email_alert = now
    _last_email_by_key[alert_key] = now
    return True


def handle_suspicious_prediction(prediction: dict) -> dict:
    message = build_alert_message(prediction)
    log_line = log_alert(message)
    sound_sent = sound_alert(prediction)
    email_sent = send_email_alert(message, prediction)
    return {
        "message": message,
        "log_line": log_line,
        "sound_sent": sound_sent,
        "email_sent": email_sent,
    }
