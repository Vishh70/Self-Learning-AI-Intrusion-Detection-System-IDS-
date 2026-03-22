from __future__ import annotations

import sys

from ids.config import MODEL_OUTPUT_CSV, PROCESSED_FEATURES_CSV, SAVED_MODEL_PATH
from ids.model import train_model


def main() -> int:
    try:
        results = train_model(
            input_csv=str(PROCESSED_FEATURES_CSV),
            output_csv=str(MODEL_OUTPUT_CSV),
            model_path=str(SAVED_MODEL_PATH),
        )
    except (FileNotFoundError, RuntimeError) as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        return 1

    print(f"[INFO] Model trained on {results['row_count']} rows.")
    print(f"[INFO] Saved model: {results['model_path']}")
    print(f"[INFO] Saved predictions: {results['output_csv']}")
    print(results["preview"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
