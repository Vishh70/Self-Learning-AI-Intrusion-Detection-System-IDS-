from __future__ import annotations

from pathlib import Path

from flask import Blueprint, Response, abort, jsonify, render_template, request, send_file

from ids.config import (
    ALERTS_LOG_PATH,
    DASHBOARD_DEFAULT_LIMIT,
    FEATURE_OUTPUT_DOWNLOAD_NAME,
    MODEL_OUTPUT_CSV,
    MODEL_OUTPUT_DOWNLOAD_NAME,
    PROCESSED_FEATURES_CSV,
    RAW_OUTPUT_CSV,
    RAW_OUTPUT_DOWNLOAD_NAME,
    REALTIME_OUTPUT_CSV,
    REALTIME_OUTPUT_DOWNLOAD_NAME,
)
from ids.dashboard import get_monitor_details, get_recent_events, get_summary, get_threat_trend, is_monitor_running
from ids.health import collect_runtime_health

main_blueprint = Blueprint("main", __name__)

DOWNLOAD_TARGETS = {
    "raw": (RAW_OUTPUT_CSV, RAW_OUTPUT_DOWNLOAD_NAME),
    "features": (PROCESSED_FEATURES_CSV, FEATURE_OUTPUT_DOWNLOAD_NAME),
    "model": (MODEL_OUTPUT_CSV, MODEL_OUTPUT_DOWNLOAD_NAME),
    "realtime": (REALTIME_OUTPUT_CSV, REALTIME_OUTPUT_DOWNLOAD_NAME),
    "alerts": (ALERTS_LOG_PATH, "alerts.log"),
}


def _bool_query_arg(name: str) -> bool:
    return request.args.get(name, "").strip().lower() in {"1", "true", "yes", "on"}


@main_blueprint.route("/", methods=["GET"])
def index():
    limit = request.args.get("limit", default=DASHBOARD_DEFAULT_LIMIT, type=int)
    suspicious_only = _bool_query_arg("suspicious_only")
    protocol = request.args.get("protocol")
    src_ip = request.args.get("src_ip")
    dst_ip = request.args.get("dst_ip")
    event_type = request.args.get("event_type")

    return render_template(
        "index.html",
        data=get_recent_events(
            limit=limit, 
            suspicious_only=suspicious_only,
            protocol=protocol,
            src_ip=src_ip,
            dst_ip=dst_ip,
            event_type=event_type
        ),
        summary=get_summary(),
        monitor_running=is_monitor_running(),
        monitor_details=get_monitor_details(),
        suspicious_only=suspicious_only,
        limit=limit,
        current_filters={
            "protocol": protocol or "",
            "src_ip": src_ip or "",
            "dst_ip": dst_ip or "",
            "event_type": event_type or "all"
        }
    )


@main_blueprint.route("/api/events", methods=["GET"])
def events():
    limit = request.args.get("limit", default=DASHBOARD_DEFAULT_LIMIT, type=int)
    suspicious_only = _bool_query_arg("suspicious_only")
    protocol = request.args.get("protocol")
    src_ip = request.args.get("src_ip")
    dst_ip = request.args.get("dst_ip")
    event_type = request.args.get("event_type")

    return jsonify(
        {
            "events": get_recent_events(
                limit=limit, 
                suspicious_only=suspicious_only,
                protocol=protocol,
                src_ip=src_ip,
                dst_ip=dst_ip,
                event_type=event_type
            ),
            "summary": get_summary(),
            "monitor_running": is_monitor_running(),
            "monitor_details": get_monitor_details(),
            "filters": {
                "limit": limit,
                "suspicious_only": suspicious_only,
                "protocol": protocol,
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "event_type": event_type
            },
        }
    )


@main_blueprint.route("/api/trend", methods=["GET"])
def trend():
    limit = request.args.get("limit", default=30, type=int)
    return jsonify({
        "trend": get_threat_trend(max_points=limit)
    })


@main_blueprint.route("/api/health", methods=["GET"])
def health():
    return jsonify(
        {
            "health": collect_runtime_health(),
            "monitor_running": is_monitor_running(),
            "monitor_details": get_monitor_details(),
        }
    )


@main_blueprint.route("/api/export", methods=["GET"])
def export_csv():
    protocol = request.args.get("protocol")
    src_ip = request.args.get("src_ip")
    dst_ip = request.args.get("dst_ip")
    event_type = request.args.get("event_type")
    
    events = get_recent_events(
        limit=2000, # Higher limit for export
        protocol=protocol,
        src_ip=src_ip,
        dst_ip=dst_ip,
        event_type=event_type
    )
    
    import io
    import csv
    
    output = io.StringIO()
    if events:
        # Merge headers across all events so mixed event types export correctly.
        header_keys = list(events[0].keys())
        all_keys = set(header_keys)
        for event in events[1:]:
            all_keys.update(event.keys())
        missing = [key for key in sorted(all_keys) if key not in header_keys]
        fieldnames = header_keys + missing

        writer = csv.DictWriter(output, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(events)
    
    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-disposition": "attachment; filename=filtered_ids_export.csv"}
    )


@main_blueprint.route("/downloads/<kind>", methods=["GET"])
def download(kind: str):
    target = DOWNLOAD_TARGETS.get(kind)
    if target is None:
        abort(404)

    file_path, download_name = target
    path = Path(file_path)
    if not path.exists():
        abort(404)

    return send_file(path, as_attachment=True, download_name=download_name)
