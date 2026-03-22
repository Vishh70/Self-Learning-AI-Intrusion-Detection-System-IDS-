from app import create_app
from ids.dashboard import add_event, clear_events


def test_dashboard_index_renders_recent_events():
    clear_events()
    add_event(
        {
            "timestamp": "2026-03-22T10:15:00",
            "src_ip": "192.168.1.10",
            "dst_ip": "8.8.8.8",
            "protocol_name": "TCP",
            "packet_length": 74,
            "anomaly": -1,
            "anomaly_label": "suspicious",
            "anomaly_score": -0.123456,
        }
    )

    app = create_app()
    client = app.test_client()
    response = client.get("/")

    assert response.status_code == 200
    body = response.get_data(as_text=True)
    assert "Self-Learning AI IDS" in body
    assert "Adapter" in body
    assert "Wi-Fi" in body
    assert "192.168.1.10" in body
    assert "suspicious" in body


def test_dashboard_api_returns_summary_and_events():
    clear_events()
    add_event(
        {
            "timestamp": "2026-03-22T10:16:00",
            "src_ip": "10.0.0.5",
            "dst_ip": "1.1.1.1",
            "protocol_name": "UDP",
            "packet_length": 68,
            "anomaly": 1,
            "anomaly_label": "normal",
            "anomaly_score": 0.456789,
        }
    )

    app = create_app()
    client = app.test_client()
    response = client.get("/api/events")

    assert response.status_code == 200
    payload = response.get_json()
    assert payload["summary"]["total"] == 1
    assert payload["summary"]["normal"] == 1
    assert payload["events"][0]["src_ip"] == "10.0.0.5"
