from __future__ import annotations

import json
from pathlib import Path

import pandas as pd

from ids.config import EVALUATION_SUMMARY_JSON, MODEL_OUTPUT_CSV


def evaluate_predictions(results_csv: str, output_json: str | None = None) -> dict:
    results_path = Path(results_csv)
    if not results_path.exists():
        raise FileNotFoundError(f"Prediction results not found: {results_path}")

    df = pd.read_csv(results_path)
    if df.empty:
        raise RuntimeError("Prediction results are empty.")
    if "anomaly" not in df.columns:
        raise RuntimeError("Prediction results are missing the anomaly column.")

    suspicious_df = df[df["anomaly"] == -1]
    total_rows = int(len(df))
    suspicious_rows = int(len(suspicious_df))
    normal_rows = total_rows - suspicious_rows
    anomaly_rate = round((suspicious_rows / total_rows) * 100, 2)

    summary = {
        "total_rows": total_rows,
        "suspicious_rows": suspicious_rows,
        "normal_rows": normal_rows,
        "anomaly_rate": anomaly_rate,
        "protocol_breakdown": df.get("protocol_name", pd.Series(dtype=str)).value_counts().to_dict(),
        "suspicious_by_protocol": suspicious_df.get("protocol_name", pd.Series(dtype=str)).value_counts().to_dict(),
        "top_source_ips": df.get("src_ip", pd.Series(dtype=str)).value_counts().head(5).to_dict(),
        "top_destination_ips": df.get("dst_ip", pd.Series(dtype=str)).value_counts().head(5).to_dict(),
        "score_distribution": {
            "min": float(df["anomaly_score"].min()),
            "q25": float(df["anomaly_score"].quantile(0.25)),
            "median": float(df["anomaly_score"].median()),
            "q75": float(df["anomaly_score"].quantile(0.75)),
            "max": float(df["anomaly_score"].max()),
        },
        "recent_suspicious_events": suspicious_df.head(10).to_dict(orient="records"),
    }

    output_path = Path(output_json or EVALUATION_SUMMARY_JSON)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(summary, indent=2, default=str), encoding="utf-8")

    return {
        "summary": summary,
        "output_json": str(output_path),
    }


def evaluate_default_results() -> dict:
    return evaluate_predictions(str(MODEL_OUTPUT_CSV), str(EVALUATION_SUMMARY_JSON))
