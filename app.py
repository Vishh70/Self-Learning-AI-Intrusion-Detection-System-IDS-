from __future__ import annotations

import argparse
import sys

from flask import Flask

from ids.capture import start_capture
from ids.config import (
    CAPTURE_MODE,
    AUTO_TRAIN_ENABLED,
    AUTO_TRAIN_INTERVAL_SECONDS,
    AUTO_TRAIN_MIN_NEW_ROWS,
    AUTO_TRAIN_MIN_TOTAL_ROWS,
    EVALUATION_SUMMARY_JSON,
    FLASK_DEBUG,
    FLASK_HOST,
    FLASK_PORT,
    INTERFACE,
    MAX_PACKETS,
    MODEL_OUTPUT_CSV,
    PCAP_PATH,
    PROCESSED_FEATURES_CSV,
    REALTIME_OUTPUT_CSV,
    RAW_OUTPUT_CSV,
    SAVED_MODEL_PATH,
)
from ids.dashboard import start_dashboard_monitor
from ids.evaluation import evaluate_predictions
from ids.features import extract_features
from ids.health import collect_runtime_health
from ids.model import train_model
from ids.auto_train import start_auto_trainer
from ids.realtime import start_realtime_detection
from ids.storage import append_rows_to_csv, write_features_csv
from ids.utils import ensure_runtime_directories, format_packet_summary, format_realtime_result
from web.routes import main_blueprint


def create_app() -> Flask:
    app = Flask(__name__)
    app.register_blueprint(main_blueprint)
    return app


def _flag_was_provided(flag_name: str) -> bool:
    return any(
        arg == flag_name or arg.startswith(f"{flag_name}=")
        for arg in sys.argv[1:]
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Self-Learning AI IDS: capture, training, realtime detection, and dashboard."
    )
    mode_group = parser.add_mutually_exclusive_group()
    mode_group.add_argument(
        "--serve",
        action="store_true",
        help="Run the Flask dashboard and start the background realtime monitor.",
    )
    mode_group.add_argument(
        "--train-model",
        action="store_true",
        help="Train the Isolation Forest model from the extracted feature dataset.",
    )
    mode_group.add_argument(
        "--realtime",
        action="store_true",
        help="Run realtime anomaly detection in the terminal.",
    )
    mode_group.add_argument(
        "--health-check",
        action="store_true",
        help="Run a runtime health check for required files and alert configuration.",
    )
    mode_group.add_argument(
        "--evaluate-model",
        action="store_true",
        help="Generate an evaluation summary from the latest model prediction CSV.",
    )
    parser.add_argument(
        "--mode",
        choices=("pcap", "live"),
        default=CAPTURE_MODE,
        help="Packet source mode.",
    )
    parser.add_argument(
        "--pcap",
        default=str(PCAP_PATH),
        help="Path to the .pcap file used in pcap mode.",
    )
    parser.add_argument(
        "--iface",
        default=INTERFACE,
        help="Network interface name for live capture. Leave blank to auto-detect.",
    )
    parser.add_argument(
        "--max-packets",
        type=int,
        default=MAX_PACKETS,
        help="Optional limit for the number of processed packets.",
    )
    parser.add_argument(
        "--features-csv",
        default=str(PROCESSED_FEATURES_CSV),
        help="Path to the extracted feature CSV used for model training.",
    )
    parser.add_argument(
        "--results-csv",
        default=str(MODEL_OUTPUT_CSV),
        help="Path to the CSV file that will store batch anomaly predictions.",
    )
    parser.add_argument(
        "--evaluation-json",
        default=str(EVALUATION_SUMMARY_JSON),
        help="Path to the JSON file that will store evaluation summary output.",
    )
    parser.add_argument(
        "--realtime-results-csv",
        default=str(REALTIME_OUTPUT_CSV),
        help="Path to the CSV file that will store realtime predictions.",
    )
    parser.add_argument(
        "--model-path",
        default=str(SAVED_MODEL_PATH),
        help="Path to the saved Isolation Forest model file.",
    )
    parser.add_argument(
        "--contamination",
        type=float,
        default=0.1,
        help="Estimated fraction of anomalies in the dataset.",
    )
    parser.add_argument(
        "--estimators",
        type=int,
        default=100,
        help="Number of trees used by the Isolation Forest model.",
    )
    parser.add_argument(
        "--persist-features",
        action="store_true",
        help="Append realtime features to the feature CSV while monitoring.",
    )
    parser.add_argument(
        "--auto-reload-model",
        action="store_true",
        help="Reload the saved model automatically when it changes on disk.",
    )
    parser.add_argument(
        "--reload-interval",
        type=int,
        default=50,
        help="How often (in predictions) to check for a newer model file.",
    )
    parser.add_argument(
        "--auto-train",
        action="store_true",
        help="Enable continuous retraining from the live feature stream.",
    )
    parser.add_argument(
        "--auto-train-interval",
        type=int,
        default=AUTO_TRAIN_INTERVAL_SECONDS,
        help="Seconds between auto-train checks.",
    )
    parser.add_argument(
        "--auto-train-min-new",
        type=int,
        default=AUTO_TRAIN_MIN_NEW_ROWS,
        help="Minimum new feature rows required before retraining.",
    )
    parser.add_argument(
        "--auto-train-min-total",
        type=int,
        default=AUTO_TRAIN_MIN_TOTAL_ROWS,
        help="Minimum total feature rows required before retraining.",
    )
    return parser


def run_capture(args: argparse.Namespace) -> int:
    ensure_runtime_directories()

    batch_size = 50
    total_raw_rows = 0
    total_feature_rows = 0
    raw_rows: list[dict] = []
    feature_rows: list[dict] = []

    def flush_batches() -> None:
        nonlocal raw_rows, feature_rows, total_raw_rows, total_feature_rows
        if raw_rows:
            append_rows_to_csv(raw_rows, str(RAW_OUTPUT_CSV))
            total_raw_rows += len(raw_rows)
            raw_rows = []
        if feature_rows:
            write_features_csv(feature_rows, str(PROCESSED_FEATURES_CSV))
            total_feature_rows += len(feature_rows)
            feature_rows = []

    try:
        for packet_summary in start_capture(
            mode=args.mode,
            pcap_path=args.pcap,
            interface=args.iface,
            max_packets=args.max_packets,
        ):
            print(format_packet_summary(packet_summary))
            raw_rows.append(packet_summary)

            feature_row = extract_features(packet_summary)
            if feature_row is not None:
                feature_rows.append(feature_row)

            if len(raw_rows) >= batch_size or len(feature_rows) >= batch_size:
                flush_batches()
    except FileNotFoundError as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        return 1
    except RuntimeError as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\n[INFO] Capture interrupted by user.")

    flush_batches()

    print(
        f"[INFO] Processed {total_raw_rows} packets and wrote "
        f"{total_feature_rows} feature rows."
    )
    return 0


def run_model_training(args: argparse.Namespace) -> int:
    ensure_runtime_directories()

    try:
        results = train_model(
            input_csv=args.features_csv,
            output_csv=args.results_csv,
            model_path=args.model_path,
            contamination=args.contamination,
            n_estimators=args.estimators,
        )
    except FileNotFoundError as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        return 1
    except RuntimeError as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        return 1

    print(f"[INFO] Model trained on {results['row_count']} rows.")
    print(f"[INFO] Saved model: {results['model_path']}")
    print(f"[INFO] Saved predictions: {results['output_csv']}")
    print(results["preview"])
    return 0


def run_realtime_detection(args: argparse.Namespace) -> int:
    ensure_runtime_directories()

    total_predictions = 0
    prediction_rows: list[dict] = []
    persist_features = args.persist_features or args.auto_train

    if args.auto_train:
        start_auto_trainer(
            features_csv=args.features_csv,
            model_path=args.model_path,
            results_csv=args.results_csv,
            contamination=args.contamination,
            n_estimators=args.estimators,
            interval_seconds=args.auto_train_interval,
            min_new_rows=args.auto_train_min_new,
            min_total_rows=args.auto_train_min_total,
        )

    try:
        for prediction in start_realtime_detection(
            mode=args.mode,
            model_path=args.model_path,
            pcap_path=args.pcap,
            interface=args.iface,
            max_packets=args.max_packets,
            persist_features=persist_features,
            auto_reload_model=args.auto_reload_model,
            reload_interval=args.reload_interval,
        ):
            print(format_realtime_result(prediction))
            prediction_rows.append(prediction)
            total_predictions += 1

            if len(prediction_rows) >= 50:
                append_rows_to_csv(prediction_rows, args.realtime_results_csv)
                prediction_rows = []
    except FileNotFoundError as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        return 1
    except RuntimeError as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\n[INFO] Realtime detection interrupted by user.")

    if prediction_rows:
        append_rows_to_csv(prediction_rows, args.realtime_results_csv)

    print(f"[INFO] Produced {total_predictions} realtime predictions.")
    return 0


def run_health_check(args: argparse.Namespace) -> int:
    health = collect_runtime_health(
        model_path=args.model_path,
        features_csv=args.features_csv,
    )
    for key, value in health.items():
        print(f"[INFO] {key}={value}")
    return 0 if health["overall_ok"] else 1


def run_evaluation(args: argparse.Namespace) -> int:
    try:
        result = evaluate_predictions(
            results_csv=args.results_csv,
            output_json=args.evaluation_json,
        )
    except (FileNotFoundError, RuntimeError) as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        return 1

    summary = result["summary"]
    print(f"[INFO] total_rows={summary['total_rows']}")
    print(f"[INFO] suspicious_rows={summary['suspicious_rows']}")
    print(f"[INFO] anomaly_rate={summary['anomaly_rate']}%")
    print(f"[INFO] summary_file={result['output_json']}")
    return 0


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    if args.serve:
        ensure_runtime_directories()
        serve_mode = args.mode if _flag_was_provided("--mode") else "live"
        serve_max_packets = args.max_packets if _flag_was_provided("--max-packets") else None
        serve_pcap_path = args.pcap if serve_mode == "pcap" else None

        auto_train_enabled = args.auto_train or AUTO_TRAIN_ENABLED
        persist_features = args.persist_features or auto_train_enabled
        auto_reload_model = args.auto_reload_model or auto_train_enabled

        start_dashboard_monitor(
            mode=serve_mode,
            model_path=args.model_path,
            pcap_path=serve_pcap_path,
            interface=args.iface,
            max_packets=serve_max_packets,
            persist_features=persist_features,
            auto_reload_model=auto_reload_model,
        )

        if auto_train_enabled:
            start_auto_trainer(
                features_csv=args.features_csv,
                model_path=args.model_path,
                results_csv=args.results_csv,
                contamination=args.contamination,
                n_estimators=args.estimators,
                interval_seconds=args.auto_train_interval,
                min_new_rows=args.auto_train_min_new,
                min_total_rows=args.auto_train_min_total,
            )

        app = create_app()
        app.run(host=FLASK_HOST, port=FLASK_PORT, debug=FLASK_DEBUG)
        return 0

    if args.train_model:
        return run_model_training(args)

    if args.realtime:
        return run_realtime_detection(args)

    if args.health_check:
        return run_health_check(args)

    if args.evaluate_model:
        return run_evaluation(args)

    return run_capture(args)


if __name__ == "__main__":
    raise SystemExit(main())
