from __future__ import annotations

import csv
from pathlib import Path


def _write_rows(rows: list[dict], path: str) -> None:
    if not rows:
        return

    output_path = Path(path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    file_exists = output_path.exists() and output_path.stat().st_size > 0
    fieldnames = []

    if file_exists:
        try:
            with output_path.open("r", newline="", encoding="utf-8") as head_check:
                reader = csv.reader(head_check)
                fieldnames = next(reader)
        except (StopIteration, Exception):
            # If we can't read a header from a non-empty file, something is wrong.
            # We'll default to the keys in the first row to at least be consistent.
            if rows:
                fieldnames = sorted(list(rows[0].keys()))
    
    # If we still don't have fieldnames (file didn't exist or was empty)
    if not fieldnames:
        all_keys = set()
        for r in rows:
            all_keys.update(r.keys())
        fieldnames = sorted(list(all_keys))

    # If new rows introduce fields not in the existing header, rewrite with merged header.
    new_keys = set()
    for r in rows:
        new_keys.update(r.keys())
    missing = new_keys.difference(fieldnames)
    if file_exists and missing:
        merged_fieldnames = list(fieldnames) + sorted(list(missing))
        existing_rows: list[dict] = []
        try:
            with output_path.open("r", newline="", encoding="utf-8") as handle:
                reader = csv.DictReader(handle)
                for row in reader:
                    existing_rows.append(row)
        except Exception:
            existing_rows = []

        with output_path.open("w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=merged_fieldnames)
            writer.writeheader()
            if existing_rows:
                writer.writerows(existing_rows)
            writer.writerows(rows)
        return

    with output_path.open("a", newline="", encoding="utf-8") as handle:
        # extrasaction='ignore' ensures we don't crash if rows have extra fields
        # that aren't in the existing CSV header.
        writer = csv.DictWriter(handle, fieldnames=fieldnames, extrasaction='ignore')
        if not file_exists:
            writer.writeheader()
        writer.writerows(rows)


def append_rows_to_csv(rows: list[dict], path: str) -> None:
    _write_rows(rows, path)


def write_features_csv(rows: list[dict], path: str) -> None:
    _write_rows(rows, path)
