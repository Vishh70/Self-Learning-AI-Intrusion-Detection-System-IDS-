from pathlib import Path

from ids.alerts import build_alert_message, handle_suspicious_prediction, log_alert


def test_build_alert_message_contains_key_context():
    message = build_alert_message(
        {
            "timestamp": "2026-03-22T10:15:00",
            "src_ip": "192.168.1.10",
            "dst_ip": "8.8.8.8",
            "protocol_name": "TCP",
            "anomaly_score": -0.123456,
        }
    )

    assert "192.168.1.10" in message
    assert "8.8.8.8" in message
    assert "TCP" in message


def test_log_alert_writes_line_to_file(tmp_path):
    log_path = tmp_path / "alerts.log"
    line = log_alert("ALERT sample", path=str(log_path))

    assert log_path.exists()
    assert "ALERT sample" in line
    assert "ALERT sample" in log_path.read_text(encoding="utf-8")


def test_handle_suspicious_prediction_logs_when_email_disabled(tmp_path, monkeypatch):
    log_path = tmp_path / "alerts.log"
    monkeypatch.setattr("ids.alerts.ALERTS_LOG_PATH", log_path)
    monkeypatch.setattr("ids.alerts.SOUND_ALERTS_ENABLED", False)
    monkeypatch.setattr("ids.alerts.EMAIL_ALERTS_ENABLED", False)

    result = handle_suspicious_prediction(
        {
            "timestamp": "2026-03-22T10:15:00",
            "src_ip": "10.0.0.5",
            "dst_ip": "1.1.1.1",
            "protocol_name": "UDP",
            "anomaly_score": -0.5,
        }
    )

    assert result["message"].startswith("ALERT")
    assert result["email_sent"] is False
    assert result["sound_sent"] is False
    assert log_path.exists()
