import pandas as pd

from ids.model import build_training_matrix, ip_to_int, train_model


def test_ip_to_int_converts_ipv4_and_handles_invalid_input():
    assert ip_to_int("192.168.1.10") > 0
    assert ip_to_int("invalid-ip") == 0


def test_build_training_matrix_creates_numeric_ip_columns():
    df = pd.DataFrame(
        [
            {
                "src_ip": "192.168.1.10",
                "dst_ip": "8.8.8.8",
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
            }
        ]
    )

    matrix = build_training_matrix(df)

    assert "src_ip_numeric" in matrix.columns
    assert "dst_ip_numeric" in matrix.columns
    assert matrix.iloc[0]["src_ip_numeric"] > 0
    assert matrix.iloc[0]["dst_ip_numeric"] > 0


def test_train_model_writes_predictions_and_model(tmp_path):
    dataset_path = tmp_path / "features.csv"
    output_path = tmp_path / "results.csv"
    model_path = tmp_path / "saved_model.pkl"

    df = pd.DataFrame(
        [
            {
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
            },
            {
                "timestamp": "2026-03-22T10:15:01",
                "src_ip": "192.168.1.11",
                "dst_ip": "1.1.1.1",
                "src_port": 50000,
                "dst_port": 53,
                "protocol_number": 17,
                "protocol_name": "UDP",
                "packet_length": 68,
                "ttl": 63,
                "is_tcp": 0,
                "is_udp": 1,
                "is_icmp": 0,
                "src_is_private": 1,
                "dst_is_private": 0,
                "tcp_flags": "",
                "has_payload": 1,
                "avg_packet_length": 68,
                "burstiness": 0.2,
                "conn_count": 2,
            },
            {
                "timestamp": "2026-03-22T10:15:02",
                "src_ip": "10.0.0.5",
                "dst_ip": "8.8.4.4",
                "src_port": 0,
                "dst_port": 0,
                "protocol_number": 1,
                "protocol_name": "ICMP",
                "packet_length": 84,
                "ttl": 128,
                "is_tcp": 0,
                "is_udp": 0,
                "is_icmp": 1,
                "src_is_private": 1,
                "dst_is_private": 0,
                "tcp_flags": "",
                "has_payload": 0,
                "avg_packet_length": 84,
                "burstiness": 0.05,
                "conn_count": 3,
            },
            {
                "timestamp": "2026-03-22T10:15:03",
                "src_ip": "172.16.0.8",
                "dst_ip": "9.9.9.9",
                "src_port": 443,
                "dst_port": 44321,
                "protocol_number": 6,
                "protocol_name": "TCP",
                "packet_length": 90,
                "ttl": 60,
                "is_tcp": 1,
                "is_udp": 0,
                "is_icmp": 0,
                "src_is_private": 1,
                "dst_is_private": 0,
                "tcp_flags": "PA",
                "has_payload": 1,
                "avg_packet_length": 90,
                "burstiness": 0.15,
                "conn_count": 4,
            },
        ]
    )
    df.to_csv(dataset_path, index=False)

    results = train_model(
        input_csv=str(dataset_path),
        output_csv=str(output_path),
        model_path=str(model_path),
        contamination=0.25,
        n_estimators=50,
    )

    assert results["row_count"] == 4
    assert output_path.exists()
    assert model_path.exists()

    output_df = pd.read_csv(output_path)
    assert "anomaly" in output_df.columns
    assert "anomaly_label" in output_df.columns
