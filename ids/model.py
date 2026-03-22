from __future__ import annotations

import ipaddress
from pathlib import Path

import joblib
import pandas as pd
from sklearn.ensemble import IsolationForest

MODEL_FEATURE_COLUMNS = [
    "src_ip_numeric",
    "dst_ip_numeric",
    "protocol_number",
    "packet_length",
    "ttl",
    "src_port",
    "dst_port",
    "is_tcp",
    "is_udp",
    "is_icmp",
    "src_is_private",
    "dst_is_private",
    "has_payload",
    "burstiness",
    "conn_count",
    "avg_packet_length",
]


def ip_to_int(ip: str) -> int:
    try:
        return int(ipaddress.ip_address(ip))
    except ValueError:
        return 0


def prepare_model_dataframe(df: pd.DataFrame) -> pd.DataFrame:
    prepared = df.copy()
    required_columns = {
        "src_ip",
        "dst_ip",
        "protocol_number",
        "packet_length",
        "ttl",
        "src_port",
        "dst_port",
        "is_tcp",
        "is_udp",
        "is_icmp",
        "src_is_private",
        "dst_is_private",
        "has_payload",
        "burstiness",
        "conn_count",
        "avg_packet_length",
    }
    missing_columns = required_columns.difference(prepared.columns)
    if missing_columns:
        missing = ", ".join(sorted(missing_columns))
        raise RuntimeError(
            f"Feature dataset is missing required columns: {missing}. "
            "Run Phase 2 capture first."
        )

    prepared["src_ip_numeric"] = prepared["src_ip"].fillna("").map(ip_to_int)
    prepared["dst_ip_numeric"] = prepared["dst_ip"].fillna("").map(ip_to_int)

    return prepared


def build_training_matrix(df: pd.DataFrame) -> pd.DataFrame:
    prepared = prepare_model_dataframe(df)
    return prepared[MODEL_FEATURE_COLUMNS].fillna(0)


def build_inference_matrix(feature_row: dict) -> pd.DataFrame:
    return build_training_matrix(pd.DataFrame([feature_row]))


def load_model(model_path: str):
    path = Path(model_path)
    if not path.exists():
        raise FileNotFoundError(
            f"Saved model not found: {path}. Run Phase 3 training first."
        )
    return joblib.load(path)


def train_model(
    input_csv: str,
    output_csv: str,
    model_path: str,
    contamination: float = 0.1,
    n_estimators: int = 100,
) -> dict:
    input_path = Path(input_csv)
    if not input_path.exists():
        raise FileNotFoundError(
            f"Feature dataset not found: {input_path}. "
            "Run packet capture first to generate packet_features.csv."
        )

    if contamination <= 0 or contamination >= 0.5:
        raise RuntimeError("Contamination must be between 0 and 0.5.")
    if n_estimators <= 0:
        raise RuntimeError("Number of estimators must be greater than zero.")

    df = pd.read_csv(input_path)
    if df.empty:
        raise RuntimeError("Feature dataset is empty. Capture packets before training.")

    prepared = prepare_model_dataframe(df)
    feature_matrix = prepared[MODEL_FEATURE_COLUMNS].fillna(0)

    model = IsolationForest(
        n_estimators=n_estimators,
        contamination=contamination,
        random_state=42,
    )
    model.fit(feature_matrix)

    prepared["anomaly"] = model.predict(feature_matrix)
    prepared["anomaly_label"] = prepared["anomaly"].map(
        {1: "normal", -1: "suspicious"}
    )
    prepared["anomaly_score"] = model.score_samples(feature_matrix)

    output_path = Path(output_csv)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    prepared.to_csv(output_path, index=False)

    model_file = Path(model_path)
    model_file.parent.mkdir(parents=True, exist_ok=True)
    
    # Calculate granular score quantiles for risk calibration (Phase 11 Refinement)
    # We store multiple percentiles to allow for non-linear mapping of threat %
    scores = prepared["anomaly_score"]
    model.calibration_stats_ = {
        "min": float(scores.min()),
        "p01": float(scores.quantile(0.01)),
        "p05": float(scores.quantile(0.05)),
        "p10": float(scores.quantile(0.1)),
        "p25": float(scores.quantile(0.25)),
        "p50": float(scores.quantile(0.5)),
        "max": float(scores.max()),
        "threshold": float(getattr(model, "offset_", -0.5))
    }
    
    joblib.dump(model, model_file)

    preview_columns = [
        column
        for column in (
            "src_ip",
            "dst_ip",
            "protocol_name",
            "packet_length",
            "anomaly",
            "anomaly_label",
            "anomaly_score",
        )
        if column in prepared.columns
    ]
    preview = prepared[preview_columns].head()

    return {
        "row_count": len(prepared),
        "output_csv": str(output_path),
        "model_path": str(model_file),
        "preview": preview.to_string(index=False),
    }
