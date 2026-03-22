from __future__ import annotations

from pathlib import Path
from threading import Event, Lock, Thread
import time

from ids.config import (
    AUTO_TRAIN_INTERVAL_SECONDS,
    AUTO_TRAIN_MIN_NEW_ROWS,
    AUTO_TRAIN_MIN_TOTAL_ROWS,
    MODEL_OUTPUT_CSV,
    PROCESSED_FEATURES_CSV,
    SAVED_MODEL_PATH,
)
from ids.model import train_model

_lock = Lock()
_thread: Thread | None = None
_stop_event = Event()
_state = {
    "enabled": False,
    "last_trained_at": "",
    "last_row_count": 0,
    "last_error": "",
}


def _count_rows(path: Path) -> int:
    if not path.exists():
        return 0
    try:
        with path.open("r", encoding="utf-8") as handle:
            return max(0, sum(1 for _ in handle) - 1)
    except Exception:
        return 0


def _should_train(row_count: int, min_total_rows: int, min_new_rows: int) -> bool:
    if row_count < min_total_rows:
        return False
    if row_count - _state["last_row_count"] < min_new_rows:
        return False
    return True


def _trainer_loop(
    features_csv: str,
    model_path: str,
    results_csv: str,
    contamination: float,
    n_estimators: int,
    interval_seconds: int,
    min_new_rows: int,
    min_total_rows: int,
) -> None:
    features_path = Path(features_csv)
    while not _stop_event.is_set():
        row_count = _count_rows(features_path)
        if _should_train(row_count, min_total_rows, min_new_rows) or (
            row_count >= min_total_rows and not Path(model_path).exists()
        ):
            try:
                train_model(
                    input_csv=features_csv,
                    output_csv=results_csv,
                    model_path=model_path,
                    contamination=contamination,
                    n_estimators=n_estimators,
                )
                with _lock:
                    _state["last_row_count"] = row_count
                    _state["last_trained_at"] = time.strftime("%Y-%m-%d %H:%M:%S")
                    _state["last_error"] = ""
            except Exception as exc:
                with _lock:
                    _state["last_error"] = str(exc)
        _stop_event.wait(interval_seconds)

    with _lock:
        _state["enabled"] = False


def start_auto_trainer(
    features_csv: str = str(PROCESSED_FEATURES_CSV),
    model_path: str = str(SAVED_MODEL_PATH),
    results_csv: str = str(MODEL_OUTPUT_CSV),
    contamination: float = 0.1,
    n_estimators: int = 100,
    interval_seconds: int = AUTO_TRAIN_INTERVAL_SECONDS,
    min_new_rows: int = AUTO_TRAIN_MIN_NEW_ROWS,
    min_total_rows: int = AUTO_TRAIN_MIN_TOTAL_ROWS,
) -> bool:
    global _thread

    if _thread is not None and _thread.is_alive():
        return False

    _stop_event.clear()
    with _lock:
        _state["enabled"] = True
        _state["last_error"] = ""

    _thread = Thread(
        target=_trainer_loop,
        kwargs={
            "features_csv": features_csv,
            "model_path": model_path,
            "results_csv": results_csv,
            "contamination": contamination,
            "n_estimators": n_estimators,
            "interval_seconds": interval_seconds,
            "min_new_rows": min_new_rows,
            "min_total_rows": min_total_rows,
        },
        daemon=True,
        name="ids-auto-trainer",
    )
    _thread.start()
    return True


def stop_auto_trainer() -> None:
    _stop_event.set()


def get_auto_train_status() -> dict:
    with _lock:
        return dict(_state)
