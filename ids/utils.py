from __future__ import annotations

from ids.config import DATA_DIR, LOGS_DIR, PROCESSED_DATA_DIR, RAW_DATA_DIR


def ensure_runtime_directories() -> None:
    for path in (DATA_DIR, RAW_DATA_DIR, PROCESSED_DATA_DIR, LOGS_DIR):
        path.mkdir(parents=True, exist_ok=True)


def format_packet_summary(packet_summary: dict) -> str:
    return (
        f"[PACKET] {packet_summary['timestamp']} "
        f"src={packet_summary['src_ip']} "
        f"dst={packet_summary['dst_ip']} "
        f"proto={packet_summary['protocol']} "
        f"len={packet_summary['packet_length']}"
    )


def format_realtime_result(result: dict) -> str:
    prefix = "[ALERT]" if result["anomaly"] == -1 else "[NORMAL]"
    return (
        f"{prefix} {result['timestamp']} "
        f"src={result['src_ip']} "
        f"dst={result['dst_ip']} "
        f"proto={result['protocol_name']} "
        f"len={result['packet_length']} "
        f"score={result['anomaly_score']:.6f} "
        f"risk={result.get('risk_score', 0.0):.1f}%"
    )
