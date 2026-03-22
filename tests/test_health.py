from ids.health import collect_runtime_health


def test_collect_runtime_health_reports_expected_flags(tmp_path):
    model_path = tmp_path / "saved_model.pkl"
    features_csv = tmp_path / "packet_features.csv"
    alerts_log = tmp_path / "alerts.log"

    model_path.write_text("model", encoding="utf-8")
    features_csv.write_text("header\n", encoding="utf-8")

    health = collect_runtime_health(
        model_path=str(model_path),
        features_csv=str(features_csv),
        alerts_log_path=str(alerts_log),
    )

    assert health["model_exists"] is True
    assert health["features_csv_exists"] is True
    assert health["alerts_log_exists"] is False
    assert "overall_ok" in health
