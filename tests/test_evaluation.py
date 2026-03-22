import json

import pandas as pd

from ids.evaluation import evaluate_predictions


def test_evaluate_predictions_writes_summary_json(tmp_path):
    results_csv = tmp_path / "model_results.csv"
    summary_json = tmp_path / "evaluation_summary.json"

    df = pd.DataFrame(
        [
            {
                "src_ip": "192.168.1.10",
                "dst_ip": "8.8.8.8",
                "protocol_name": "TCP",
                "anomaly": 1,
                "anomaly_score": 0.45,
            },
            {
                "src_ip": "10.0.0.5",
                "dst_ip": "1.1.1.1",
                "protocol_name": "UDP",
                "anomaly": -1,
                "anomaly_score": -0.12,
            },
        ]
    )
    df.to_csv(results_csv, index=False)

    result = evaluate_predictions(str(results_csv), str(summary_json))

    assert result["summary"]["total_rows"] == 2
    assert result["summary"]["suspicious_rows"] == 1
    assert summary_json.exists()

    payload = json.loads(summary_json.read_text(encoding="utf-8"))
    assert payload["anomaly_rate"] == 50.0
