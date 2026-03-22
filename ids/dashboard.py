from __future__ import annotations

from collections import deque
from datetime import datetime
from threading import Lock, Thread

from ids.config import DASHBOARD_DEFAULT_LIMIT, DASHBOARD_MAX_LIMIT
from ids.capture import detect_connected_ssid, resolve_live_interface
from ids.realtime import start_realtime_detection

_events: deque[dict] = deque(maxlen=200)
_total_processed_packets = 0
_lock = Lock()
_worker_thread: Thread | None = None
_monitor_details = {
    "mode": "idle",
    "requested_interface": "",
    "active_interface": "",
    "ssid": "",
    "bssid": "",
    "pcap_path": "",
}


def add_event(event: dict) -> None:
    global _total_processed_packets
    # Synthetic events (Watchdog, System) should not count as 'Scanned Packets'
    is_real_packet = event.get("src_ip") not in ("WATCHDOG", "SYSTEM")
    
    with _lock:
        _events.appendleft(dict(event))
        if is_real_packet:
            _total_processed_packets += 1


def get_recent_events(
    limit: int = DASHBOARD_DEFAULT_LIMIT,
    suspicious_only: bool = False,
    protocol: str | None = None,
    src_ip: str | None = None,
    dst_ip: str | None = None,
    event_type: str | None = None,
) -> list[dict]:
    with _lock:
        items = list(_events)
        
    if suspicious_only:
        items = [e for e in items if e.get("anomaly") == -1]
    
    if protocol:
        p_upper = protocol.upper()
        items = [e for e in items if e.get("protocol_name") == p_upper]
        
    if src_ip:
        items = [e for e in items if src_ip in str(e.get("src_ip", ""))]
        
    if dst_ip:
        items = [e for e in items if dst_ip in str(e.get("dst_ip", ""))]
        
    # Default to 'all' so the UI "All Events" matches backend behavior
    effective_type = event_type if event_type else "all"
    
    if effective_type == "traffic":
        items = [e for e in items if e.get("src_ip") not in ("WATCHDOG", "SYSTEM")]
    elif effective_type == "system":
        items = [e for e in items if e.get("src_ip") == "SYSTEM"]
    elif effective_type == "watchdog":
        items = [e for e in items if e.get("src_ip") == "WATCHDOG"]

    # If effective_type is 'all', we don't apply an exclusion filter

    safe_limit = max(1, min(limit, DASHBOARD_MAX_LIMIT))
    return items[:safe_limit]


def get_threat_trend(max_points: int = 30) -> list[dict]:
    """Returns a list of trend points for a time-series chart."""
    with _lock:
        items = list(_events)
    
    # Filter for real traffic and sort by time
    traffic = [e for e in items if e.get("src_ip") not in ("WATCHDOG", "SYSTEM")]
    def _parse_ts(value: str) -> float:
        try:
            return datetime.fromisoformat(value).timestamp()
        except Exception:
            return float("-inf")

    traffic.sort(key=lambda x: _parse_ts(str(x.get("timestamp", ""))))
    
    # Group by timestamp (simplified grouping)
    trend_data = []
    seen_times = set()
    
    for event in traffic:
        ts = event.get("timestamp", "")
        if not ts: continue
        
        # Take the maximum risk score per timestamp for the graph
        risk = float(event.get("risk_score", 0))
        
        if ts in seen_times:
            # Update the peak risk for this point
            trend_data[-1]["risk"] = max(trend_data[-1]["risk"], risk)
        else:
            seen_times.add(ts)
            trend_data.append({"timestamp": ts, "risk": risk})
            
    return trend_data[-max_points:]


def get_summary() -> dict:
    with _lock:
        # Only count real packets for totals and anomaly rate (exclude Watchdog/System alerts)
        real_events = [e for e in _events if e.get("src_ip") not in ("WATCHDOG", "SYSTEM")]
        total_real = len(real_events)
        
        suspicious = sum(1 for event in real_events if event.get("anomaly") == -1)
        scanned = _total_processed_packets
        
        # We still return the visual 'total' for the UI window if needed, 
        # but the rate should be pure traffic.
        visual_total = len(_events)
        
    return {
        "total": visual_total,
        "suspicious": suspicious,
        "normal": total_real - suspicious,
        "anomaly_rate": 0.0 if total_real == 0 else round((suspicious / total_real) * 100, 2),
        "total_scanned": scanned,
    }


def clear_events() -> None:
    global _total_processed_packets
    with _lock:
        _events.clear()
        _total_processed_packets = 0


def get_monitor_details() -> dict:
    with _lock:
        return dict(_monitor_details)


def _worker(
    mode: str,
    model_path: str,
    pcap_path: str | None,
    interface: str | None,
    max_packets: int | None,
    persist_features: bool,
    auto_reload_model: bool,
) -> None:
    retry_count = 0
    max_retries = 10
    
    while retry_count < max_retries:
        try:
            # Get baseline BSSID for Watchdog
            _, initial_bssid = detect_connected_ssid(interface)
            
            # Generator for results
            results_gen = start_realtime_detection(
                mode=mode,
                model_path=model_path,
                pcap_path=pcap_path,
                interface=interface,
                max_packets=max_packets,
                persist_features=persist_features,
                auto_reload_model=auto_reload_model,
            )
            
            # Reset retry count if we successfully started
            retry_count = 0
            
            counter = 0
            for result in results_gen:
                add_event(result)
                
                # Every 50 packets, check if the network changed (Watchdog)
                counter += 1
                if counter % 50 == 0 and mode == "live":
                    _, current_bssid = detect_connected_ssid(interface)
                    if initial_bssid and current_bssid and initial_bssid != current_bssid:
                        # NETWORK CHANGE DETECTED - Possible Evil Twin
                        alert = {
                            "timestamp": result.get("timestamp"),
                            "src_ip": "WATCHDOG",
                            "dst_ip": "LOCAL",
                            "protocol_name": "SECURITY",
                            "packet_length": 0,
                            "anomaly": -1,
                            "anomaly_label": "NETWORK CHANGE",
                            "risk_score": 100.0,
                            "anomaly_score": 1.0,
                            "info": f"CRITICAL: Router MAC changed from {initial_bssid} to {current_bssid}"
                        }
                        add_event(alert)
                        # Update baseline to prevent spamming
                        initial_bssid = current_bssid
            
            # If generator ends naturally (max_packets or error), break the while loop
            break
            
        except Exception as e:
            # AUTO-SCAN RETRY LOGIC - Check if error is fatal (config/model/permission)
            err_msg = str(e).lower()
            is_fatal = any(x in err_msg for x in ("not found", "permission denied", "administrator", "model", "feature", "unseen"))
            
            retry_count += 1
            import time
            
            error_event = {
                "timestamp": time.strftime("%H:%M:%S"),
                "src_ip": "SYSTEM",
                "dst_ip": "ERROR",
                "protocol_name": "RETRY",
                "packet_length": 0,
                "anomaly": -1,
                "anomaly_label": "AUTO-SCAN",
                "risk_score": 0.0,
                "anomaly_score": 0.0,
                "info": f"Error: {str(e)}. " + ("Stopping." if is_fatal else f"Retry {retry_count}/{max_retries} in 5s...")
            }
            add_event(error_event)
            
            if is_fatal or retry_count >= max_retries:
                fatal_event = dict(error_event)
                if not is_fatal:
                    fatal_event["info"] = "FATAL: Maximum retries exceeded. Monitor stopped."
                add_event(fatal_event)
                break
                
            time.sleep(5)
            continue
    
    global _worker_thread
    _worker_thread = None


def start_dashboard_monitor(
    mode: str,
    model_path: str,
    pcap_path: str | None = None,
    interface: str | None = None,
    max_packets: int | None = None,
    persist_features: bool = False,
    auto_reload_model: bool = False,
) -> bool:
    global _worker_thread

    if _worker_thread is not None and _worker_thread.is_alive():
        return False

    clear_events()

    active_interface = ""
    ssid = ""
    bssid = ""
    full_ssid = ""
    
    if mode == "live":
        active_interface = resolve_live_interface(interface) or ""
        ssid, bssid = detect_connected_ssid(active_interface)
        if bssid:
            full_ssid = f"{ssid} [Router: {bssid}]"
        else:
            full_ssid = ssid or ""

    with _lock:
        _monitor_details.update(
            {
                "mode": mode,
                "requested_interface": interface or "",
                "active_interface": active_interface,
                "ssid": full_ssid,
                "bssid": bssid or "",
                "pcap_path": pcap_path or "",
            }
        )

    _worker_thread = Thread(
        target=_worker,
        kwargs={
            "mode": mode,
            "model_path": model_path,
            "pcap_path": pcap_path,
            "interface": active_interface or interface,  # Use resolved interface
            "max_packets": max_packets,
            "persist_features": persist_features,
            "auto_reload_model": auto_reload_model,
        },
        daemon=True,
        name="ids-dashboard-monitor",
    )
    _worker_thread.start()
    return True


def is_monitor_running() -> bool:
    return _worker_thread is not None and _worker_thread.is_alive()
