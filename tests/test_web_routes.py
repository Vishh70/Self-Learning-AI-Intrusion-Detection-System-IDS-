from pathlib import Path

from app import create_app
from ids.dashboard import add_event, clear_events


def test_events_api_supports_limit_and_suspicious_filter():
    clear_events()
    add_event(
        {
            "timestamp": "2026-03-22T10:15:01",
            "src_ip": "10.0.0.5",
            "dst_ip": "1.1.1.1",
            "protocol_name": "UDP",
            "packet_length": 68,
            "anomaly": 1,
            "anomaly_label": "normal",
            "anomaly_score": 0.45,
        }
    )
    add_event(
        {
            "timestamp": "2026-03-22T10:15:00",
            "src_ip": "192.168.1.10",
            "dst_ip": "8.8.8.8",
            "protocol_name": "TCP",
            "packet_length": 74,
            "anomaly": -1,
            "anomaly_label": "suspicious",
            "anomaly_score": -0.12,
        }
    )

    app = create_app()
    client = app.test_client()
    response = client.get("/api/events?limit=1&suspicious_only=true")

    assert response.status_code == 200
    payload = response.get_json()
    assert payload["filters"]["suspicious_only"] is True
    assert len(payload["events"]) == 1
    assert payload["events"][0]["anomaly"] == -1
    assert "monitor_details" in payload


def test_download_route_returns_existing_alert_log(tmp_path, monkeypatch):
    alert_log = tmp_path / "alerts.log"
    alert_log.write_text("sample alert\n", encoding="utf-8")
    monkeypatch.setattr("web.routes.ALERTS_LOG_PATH", alert_log)
    monkeypatch.setitem(web_download_targets(), "alerts", (alert_log, "alerts.log"))

    app = create_app()
    client = app.test_client()
    response = client.get("/downloads/alerts")

    assert response.status_code == 200
    assert response.data.strip() == b"sample alert"


def web_download_targets():
    from web.routes import DOWNLOAD_TARGETS

    return DOWNLOAD_TARGETS
