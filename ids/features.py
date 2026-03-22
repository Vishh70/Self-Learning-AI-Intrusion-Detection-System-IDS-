from __future__ import annotations

import ipaddress
from datetime import datetime

from scapy.layers.inet import IP, TCP, UDP

from collections import deque
import time

PROTOCOL_NAMES = {
    1: "ICMP",
    6: "TCP",
    17: "UDP",
}

# State for temporal/flow features
_packet_history: deque[tuple[float, str, str, int]] = deque(maxlen=1000)

def extract_protocol_name(proto_num: int) -> str:
    return PROTOCOL_NAMES.get(int(proto_num), "OTHER")


def is_private_ip(ip: str) -> int:
    try:
        return int(ipaddress.ip_address(ip).is_private)
    except ValueError:
        return 0


def _int_value(value, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _resolve_value(packet_summary: dict, key: str, fallback=0):
    value = packet_summary.get(key, fallback)
    return fallback if value is None else value


def extract_features(packet_summary: dict, packet=None) -> dict | None:
    if not packet_summary:
        return None

    ts_value = packet_summary.get("timestamp")
    if isinstance(ts_value, str) and ts_value:
        try:
            now = datetime.fromisoformat(ts_value).timestamp()
        except (ValueError, OSError, TypeError):
            now = time.time()
    else:
        now = time.time()
    protocol_number = _int_value(packet_summary.get("protocol", 0), default=0)
    src_ip = str(packet_summary.get("src_ip", ""))
    dst_ip = str(packet_summary.get("dst_ip", ""))
    length = _int_value(packet_summary.get("packet_length", 0), default=0)
    
    # Store history for flow features (timestamp, src, dst, length)
    _packet_history.append((now, src_ip, dst_ip, length))

    # Calculate temporal features
    one_sec_ago = now - 1.0
    ten_sec_ago = now - 10.0
    
    recent_packets = [p for p in _packet_history if p[0] > ten_sec_ago]
    burst_packets = [p for p in recent_packets if p[0] > one_sec_ago]
    
    # connections to the same target in the last 10s
    conn_count = sum(1 for p in recent_packets if p[1] == src_ip and p[2] == dst_ip)
    # total packets in the last 1s (burstiness)
    burstiness = len(burst_packets)
    # Average packet length in the last 10s
    avg_len = sum(p[3] for p in recent_packets) / len(recent_packets) if recent_packets else length

    src_port = _int_value(_resolve_value(packet_summary, "src_port", 0), default=0)
    dst_port = _int_value(_resolve_value(packet_summary, "dst_port", 0), default=0)
    ttl = _int_value(_resolve_value(packet_summary, "ttl", 0), default=0)
    tcp_flags = str(_resolve_value(packet_summary, "tcp_flags", ""))
    has_payload = _int_value(_resolve_value(packet_summary, "has_payload", 0), default=0)

    if packet is not None and hasattr(packet, "haslayer") and packet.haslayer(IP):
        ip_layer = packet[IP]
        protocol_number = _int_value(getattr(ip_layer, "proto", protocol_number))
        ttl = _int_value(getattr(ip_layer, "ttl", ttl))

        if packet.haslayer(TCP):
            src_port = _int_value(getattr(packet[TCP], "sport", src_port))
            dst_port = _int_value(getattr(packet[TCP], "dport", dst_port))
            tcp_flags = str(getattr(packet[TCP], "flags", tcp_flags))
        elif packet.haslayer(UDP):
            src_port = _int_value(getattr(packet[UDP], "sport", src_port))
            dst_port = _int_value(getattr(packet[UDP], "dport", dst_port))

    protocol_name = extract_protocol_name(protocol_number)

    return {
        "timestamp": str(packet_summary.get("timestamp", "")),
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": src_port,
        "dst_port": dst_port,
        "protocol_number": protocol_number,
        "protocol_name": protocol_name,
        "packet_length": length,
        "ttl": ttl,
        "is_tcp": int(protocol_number == 6),
        "is_udp": int(protocol_number == 17),
        "is_icmp": int(protocol_number == 1),
        "src_is_private": is_private_ip(src_ip),
        "dst_is_private": is_private_ip(dst_ip),
        "tcp_flags": tcp_flags,
        "has_payload": int(has_payload > 0),
        # New enriched features
        "burstiness": burstiness,
        "conn_count": conn_count,
        "avg_packet_length": round(avg_len, 2),
    }
