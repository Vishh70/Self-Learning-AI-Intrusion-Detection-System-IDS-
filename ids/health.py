from __future__ import annotations

from pathlib import Path

from ids.config import (
    ALERTS_LOG_PATH,
    EMAIL_ALERTS_ENABLED,
    PROCESSED_FEATURES_CSV,
    SAVED_MODEL_PATH,
    SMTP_PASSWORD,
    SMTP_RECEIVER,
    SMTP_SENDER,
)


def collect_runtime_health(
    model_path: str | None = None,
    features_csv: str | None = None,
    alerts_log_path: str | None = None,
) -> dict:
    model = Path(model_path or SAVED_MODEL_PATH)
    features = Path(features_csv or PROCESSED_FEATURES_CSV)
    alerts_log = Path(alerts_log_path or ALERTS_LOG_PATH)

    email_ready = all([SMTP_SENDER, SMTP_RECEIVER, SMTP_PASSWORD])
    checks = {
        "model_exists": model.exists(),
        "features_csv_exists": features.exists(),
        "alerts_log_exists": alerts_log.exists(),
        "email_enabled": EMAIL_ALERTS_ENABLED,
        "email_ready": email_ready,
    }
    checks["overall_ok"] = checks["model_exists"] and checks["features_csv_exists"]
    return checks
