from __future__ import annotations

import pandas as pd

from ids.alerts import handle_suspicious_prediction
from ids.capture import start_capture
from ids.features import extract_features
from ids.model import build_inference_matrix, load_model


def _align_features_for_model(matrix: pd.DataFrame, model) -> pd.DataFrame:
    feature_names = getattr(model, "feature_names_in_", None)
    if feature_names is None:
        return matrix

    aligned = pd.DataFrame()
    for name in feature_names:
        if name in matrix.columns:
            aligned[name] = matrix[name]
        else:
            aligned[name] = 0
    return aligned


def predict_feature_row(model, feature_row: dict) -> dict:
    matrix = build_inference_matrix(feature_row)
    matrix = _align_features_for_model(matrix, model)
    use_numpy = getattr(model, "feature_names_in_", None) is None
    model_input = matrix.to_numpy() if use_numpy else matrix
    anomaly = int(model.predict(model_input)[0])

    # Keep the raw Isolation Forest score for debugging and logs.
    raw_score = float(model.score_samples(model_input)[0])

    # Heuristic dashboard risk score derived from the raw score.
    # We use the model's internal offset if available, otherwise default to -0.5.
    threshold = getattr(model, "offset_", -0.5)
    
    if raw_score >= threshold:
        risk_score = 0.0
    else:
        # Phase 11 Refinement: Multi-point quantile interpolation
        stats = getattr(model, "calibration_stats_", None)
        if stats and "p01" in stats:
            # We map scores (lower is more anomalous) to Risk % (higher)
            # Threshold is ~0%, Min is 100%
            # x values (scores) must be increasing for interp, so we negate them
            # or use a simple sorted lookup.
            
            points = [
                (stats["threshold"], 0.0),
                (stats["p50"], 20.0),
                (stats["p25"], 40.0),
                (stats["p10"], 60.0),
                (stats["p05"], 80.0),
                (stats["p01"], 95.0),
                (stats["min"], 100.0)
            ]
            # Ensure uniqueness and sort by score (x)
            points = sorted(list({p[0]: p for p in points}.values()), key=lambda x: x[0])
            
            # Linear interpolation
            risk_score = 100.0 # Default if beyond min
            for i in range(len(points) - 1):
                x1, y1 = points[i]
                x2, y2 = points[i+1]
                # Note: scores are usually negative, e.g. -0.5 is 'normal', -0.8 is 'suspicious'
                # So x1 < x2 means x1 is more anomalous if they were positive, 
                # but physically x1 is more anomalous if it's smaller (e.g. -1.0 < -0.5)
                if x1 <= raw_score <= x2:
                    # Simple lerp: y = y1 + (x - x1) * (y2 - y1) / (x2 - x1)
                    risk_score = y1 + (raw_score - x1) * (y2 - y1) / (x2 - x1)
                    break
                elif raw_score < points[0][0]:
                    risk_score = 100.0
                    break
        else:
            # Fallback to the improved heuristic from Phase 8
            lower_bound = -1.5
            intensity_range = abs(lower_bound - threshold)
            if intensity_range > 0:
                risk_score = (abs(raw_score - threshold) / intensity_range) * 100.0
            else:
                risk_score = 100.0

    result = dict(feature_row)
    result["anomaly"] = anomaly
    result["anomaly_label"] = "suspicious" if anomaly == -1 else "normal"
    result["anomaly_score"] = raw_score
    result["risk_score"] = round(risk_score, 1)
    return result


def start_realtime_detection(
    mode: str,
    model_path: str,
    pcap_path: str | None = None,
    interface: str | None = None,
    max_packets: int | None = None,
    enable_alerts: bool = True,
):
    model = load_model(model_path)

    for packet_summary in start_capture(
        mode=mode,
        pcap_path=pcap_path,
        interface=interface,
        max_packets=max_packets,
    ):
        feature_row = extract_features(packet_summary)
        if feature_row is None:
            continue

        prediction = predict_feature_row(model, feature_row)
        prediction["timestamp"] = packet_summary.get("timestamp", "")
        prediction["alert_message"] = ""
        prediction["email_alert_sent"] = False
        prediction["sound_alert_sent"] = False
        prediction["log_alert_sent"] = False

        if enable_alerts and prediction["anomaly"] == -1:
            alert_result = handle_suspicious_prediction(prediction)
            prediction["alert_message"] = alert_result["message"]
            prediction["email_alert_sent"] = alert_result["email_sent"]
            prediction["sound_alert_sent"] = alert_result["sound_sent"]
            prediction["log_alert_sent"] = True

        yield prediction
