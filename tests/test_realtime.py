import joblib
import pandas as pd
from sklearn.ensemble import IsolationForest

from ids.realtime import predict_feature_row, start_realtime_detection


def _training_frame() -> pd.DataFrame:
    return pd.DataFrame(
        [
            {
                "src_ip_numeric": 3232235786,
                "dst_ip_numeric": 134744072,
                "protocol_number": 6,
                "packet_length": 74,
                "ttl": 64,
                "src_port": 12345,
                "dst_port": 80,
                "is_tcp": 1,
                "is_udp": 0,
                "is_icmp": 0,
                "src_is_private": 1,
                "dst_is_private": 0,
                "has_payload": 1,
                "avg_packet_length": 74,
                "burstiness": 0.1,
                "conn_count": 1,
            },
            {
                "src_ip_numeric": 3232235787,
                "dst_ip_numeric": 16843009,
                "protocol_number": 17,
                "packet_length": 68,
                "ttl": 63,
                "src_port": 50000,
                "dst_port": 53,
                "is_tcp": 0,
                "is_udp": 1,
                "is_icmp": 0,
                "src_is_private": 1,
                "dst_is_private": 0,
                "has_payload": 1,
                "avg_packet_length": 68,
                "burstiness": 0.2,
                "conn_count": 2,
            },
            {
                "src_ip_numeric": 167772165,
                "dst_ip_numeric": 134743044,
                "protocol_number": 1,
                "packet_length": 84,
                "ttl": 128,
                "src_port": 0,
                "dst_port": 0,
                "is_tcp": 0,
                "is_udp": 0,
                "is_icmp": 1,
                "src_is_private": 1,
                "dst_is_private": 0,
                "has_payload": 0,
                "avg_packet_length": 84,
                "burstiness": 0.05,
                "conn_count": 3,
            },
        ]
    )


def _feature_row() -> dict:
    return {
        "timestamp": "2026-03-22T10:15:00",
        "src_ip": "192.168.1.10",
        "dst_ip": "8.8.8.8",
        "src_port": 12345,
        "dst_port": 80,
        "protocol_number": 6,
        "protocol_name": "TCP",
        "packet_length": 74,
        "ttl": 64,
        "is_tcp": 1,
        "is_udp": 0,
        "is_icmp": 0,
        "src_is_private": 1,
        "dst_is_private": 0,
        "tcp_flags": "S",
        "has_payload": 1,
        "avg_packet_length": 74,
        "burstiness": 0.1,
        "conn_count": 1,
    }


def test_predict_feature_row_adds_anomaly_fields():
    model = IsolationForest(n_estimators=25, contamination=0.25, random_state=42)
    model.fit(_training_frame())

    result = predict_feature_row(model, _feature_row())

    assert result["anomaly"] in (-1, 1)
    assert result["anomaly_label"] in ("normal", "suspicious")
    assert isinstance(result["anomaly_score"], float)


def test_start_realtime_detection_replays_pcap_with_saved_model(tmp_path):
    model = IsolationForest(n_estimators=25, contamination=0.25, random_state=42)
    model.fit(_training_frame())

    model_path = tmp_path / "saved_model.pkl"
    joblib.dump(model, model_path)

    results = list(
        start_realtime_detection(
            mode="pcap",
            model_path=str(model_path),
            pcap_path="data/raw/sample.pcap",
            max_packets=1,
            enable_alerts=False,
        )
    )

    assert len(results) == 1
    assert results[0]["anomaly"] in (-1, 1)
    assert results[0]["protocol_name"] == "TCP"


def test_start_realtime_detection_records_alert_fields(tmp_path, monkeypatch):
    model = IsolationForest(n_estimators=25, contamination=0.25, random_state=42)
    model.fit(_training_frame())

    model_path = tmp_path / "saved_model.pkl"
    joblib.dump(model, model_path)

    monkeypatch.setattr(
        "ids.realtime.handle_suspicious_prediction",
        lambda prediction: {
            "message": "ALERT test",
            "log_line": "logged",
            "sound_sent": True,
            "email_sent": False,
        },
    )

    results = list(
        start_realtime_detection(
            mode="pcap",
            model_path=str(model_path),
            pcap_path="data/raw/sample.pcap",
            max_packets=1,
            enable_alerts=True,
        )
    )

    assert len(results) == 1
    assert "alert_message" in results[0]
    assert "email_alert_sent" in results[0]
    assert "sound_alert_sent" in results[0]
