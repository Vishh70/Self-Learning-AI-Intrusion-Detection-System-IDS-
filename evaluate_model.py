from __future__ import annotations

import sys

from ids.config import EVALUATION_SUMMARY_JSON, MODEL_OUTPUT_CSV
from ids.evaluation import evaluate_predictions


def main() -> int:
    try:
        result = evaluate_predictions(
            results_csv=str(MODEL_OUTPUT_CSV),
            output_json=str(EVALUATION_SUMMARY_JSON),
        )
    except (FileNotFoundError, RuntimeError) as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        return 1

    summary = result["summary"]
    print("MODEL EVALUATION SUMMARY")
    print(f"- total rows: {summary['total_rows']}")
    print(f"- suspicious rows: {summary['suspicious_rows']}")
    print(f"- normal rows: {summary['normal_rows']}")
    print(f"- anomaly rate: {summary['anomaly_rate']}%")
    print(f"- saved summary: {result['output_json']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
