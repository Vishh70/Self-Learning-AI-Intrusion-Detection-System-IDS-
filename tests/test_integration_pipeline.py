from pathlib import Path

from app import create_app
from ids.dashboard import add_event, clear_events
from ids.features import extract_features
from ids.capture import read_pcap
from ids.model import train_model
from ids.realtime import start_realtime_detection
import pandas as pd


def test_end_to_end_pipeline_with_sample_pcap(tmp_path):
    sample_pcap = Path("data/raw/sample.pcap")
    packet_rows = list(read_pcap(str(sample_pcap), max_packets=1))

    assert len(packet_rows) == 1

    feature = extract_features(packet_rows[0])
    assert feature is not None

    dataset_rows = []
    for index, dst_ip in enumerate(["8.8.8.8", "1.1.1.1", "8.8.4.4", "9.9.9.9"]):
        row = dict(feature)
        row["timestamp"] = f"2026-03-22T10:15:0{index}"
        row["dst_ip"] = dst_ip
        row["dst_port"] = 80 + index
        row["packet_length"] = row["packet_length"] + index
        dataset_rows.append(row)

    dataset_csv = tmp_path / "features.csv"
    results_csv = tmp_path / "results.csv"
    model_path = tmp_path / "saved_model.pkl"
    pd.DataFrame(dataset_rows).to_csv(dataset_csv, index=False)

    training_result = train_model(
        input_csv=str(dataset_csv),
        output_csv=str(results_csv),
        model_path=str(model_path),
        contamination=0.25,
        n_estimators=25,
    )

    assert training_result["row_count"] == 4
    assert results_csv.exists()
    assert model_path.exists()

    realtime_rows = list(
        start_realtime_detection(
            mode="pcap",
            model_path=str(model_path),
            pcap_path=str(sample_pcap),
            max_packets=1,
            enable_alerts=False,
        )
    )
    assert len(realtime_rows) == 1

    clear_events()
    add_event(realtime_rows[0])
    app = create_app()
    client = app.test_client()
    assert client.get("/").status_code == 200
    assert client.get("/api/events").status_code == 200
