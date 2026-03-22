from __future__ import annotations

from datetime import datetime
from pathlib import Path
from queue import Empty, Queue
import subprocess
import sys
from typing import Iterator

from scapy.all import AsyncSniffer, PcapReader, Raw, conf
from scapy.layers.inet import ICMP, IP, TCP, UDP


def process_packet(packet) -> dict | None:
    """Return a normalized packet summary for IPv4 packets."""
    try:
        if not packet.haslayer(IP):
            return None

        ip_layer = packet[IP]
        summary = {
            "timestamp": datetime.fromtimestamp(float(packet.time)).isoformat(
                timespec="seconds"
            ),
            "src_ip": str(ip_layer.src),
            "dst_ip": str(ip_layer.dst),
            "protocol": int(ip_layer.proto),
            "packet_length": int(len(packet)),
            "ttl": int(getattr(ip_layer, "ttl", 0) or 0),
            "src_port": 0,
            "dst_port": 0,
            "tcp_flags": "",
            "has_payload": 0,
        }

        if packet.haslayer(TCP):
            tcp_layer = packet[TCP]
            summary["src_port"] = int(getattr(tcp_layer, "sport", 0) or 0)
            summary["dst_port"] = int(getattr(tcp_layer, "dport", 0) or 0)
            summary["tcp_flags"] = str(getattr(tcp_layer, "flags", ""))
        elif packet.haslayer(UDP):
            udp_layer = packet[UDP]
            summary["src_port"] = int(getattr(udp_layer, "sport", 0) or 0)
            summary["dst_port"] = int(getattr(udp_layer, "dport", 0) or 0)
        elif packet.haslayer(ICMP):
            summary["src_port"] = 0
            summary["dst_port"] = 0

        if packet.haslayer(Raw):
            payload = bytes(packet[Raw])
            summary["has_payload"] = int(len(payload) > 0)

        return summary
    except Exception:
        return None


def detect_active_interface() -> str | None:
    """Return Scapy's current default interface name when available."""
    iface = getattr(conf, "iface", None)
    if iface is None:
        return None

    iface_name = getattr(iface, "name", iface)
    if iface_name is None:
        return None

    iface_name = str(iface_name).strip()
    return iface_name or None


def resolve_live_interface(interface: str | None = None) -> str | None:
    """Use the requested interface or fall back to the active default interface."""
    target = (interface or "").strip().lower()
    
    # If no target, try to find a default
    if not target:
        return detect_active_interface()

    # Try to find a case-insensitive match in Scapy's interface list
    # This helps when the user types 'WiFi' but Windows calls it 'Wi-Fi'
    from scapy.all import get_if_list
    try:
        if_list = get_if_list()
        for iface in if_list:
            if iface.lower() == target:
                return iface
            # Also check for common Windows variations
            clean_iface = iface.lower().replace("-", "").replace(" ", "")
            clean_target = target.replace("-", "").replace(" ", "")
            if clean_iface == clean_target:
                return iface
    except Exception:
        pass

    return interface or detect_active_interface()


def detect_connected_ssid(interface: str | None = None) -> tuple[str | None, str | None]:
    """Return the connected Wi-Fi (SSID, BSSID) on Windows when available."""
    if not sys.platform.startswith("win"):
        return None, None

    try:
        result = subprocess.run(
            ["netsh", "wlan", "show", "interfaces"],
            capture_output=True,
            text=True,
            check=True,
        )
    except Exception:
        return None, None

    target_interface = (interface or "").strip().lower()
    current_name = ""
    current_ssid = ""

    for raw_line in result.stdout.splitlines():
        line = raw_line.strip()
        if not line or ":" not in line:
            continue

        key, value = [part.strip() for part in line.split(":", 1)]
        key_lower = key.lower()
        if key_lower == "name":
            current_name = (value or "").strip()
        elif key_lower == "ssid" and not key_lower.startswith("bssid"):
            current_ssid = value
        elif key_lower.startswith("bssid") and current_ssid:
            # Flexible comparison for interface name (WiFi vs Wi-Fi)
            match = False
            if not target_interface:
                match = True
            else:
                c1 = current_name.lower().replace("-", "").replace(" ", "")
                c2 = target_interface.replace("-", "").replace(" ", "")
                if c1 == c2:
                    match = True
            
            if match:
                return current_ssid, value

    # Fallback if BSSID was not found
    match = False
    if current_ssid:
        if not target_interface:
            match = True
        else:
            c1 = current_name.lower().replace("-", "").replace(" ", "")
            c2 = target_interface.replace("-", "").replace(" ", "")
            if c1 == c2:
                match = True

    if match:
        return current_ssid, None

    return None, None


def sniff_live(
    interface: str | None = None, max_packets: int | None = None
) -> Iterator[dict]:
    """Yield packet summaries from live traffic."""
    packet_queue = Queue()
    processed_count = 0
    selected_interface = resolve_live_interface(interface)

    def _callback(packet) -> None:
        summary = process_packet(packet)
        if summary is not None:
            packet_queue.put(summary)

    sniffer = AsyncSniffer(iface=selected_interface, prn=_callback, store=False)

    try:
        sniffer.start()
    except Exception as exc:
        raise RuntimeError(
            "Live capture could not start. Run as Administrator and confirm "
            "Npcap is installed, or switch to --mode pcap. "
            f"Selected interface: {selected_interface or 'auto-detect failed'}."
        ) from exc

    try:
        while True:
            try:
                summary = packet_queue.get(timeout=0.25)
            except Empty:
                if not sniffer.running:
                    break
                continue

            yield summary
            processed_count += 1

            if max_packets is not None and max_packets > 0 and processed_count >= max_packets:
                break
    finally:
        if sniffer.running:
            sniffer.stop()


def read_pcap(path: str, max_packets: int | None = None) -> Iterator[dict]:
    """Yield packet summaries from an offline .pcap file."""
    pcap_path = Path(path)
    if not pcap_path.exists():
        raise FileNotFoundError(f"PCAP file not found: {pcap_path}")

    processed_count = 0
    reader = PcapReader(str(pcap_path))
    try:
        for packet in reader:
            summary = process_packet(packet)
            if summary is None:
                continue

            yield summary
            processed_count += 1

            if max_packets is not None and max_packets > 0 and processed_count >= max_packets:
                break
    finally:
        reader.close()


def start_capture(mode: str, **kwargs) -> Iterator[dict]:
    """Dispatch packet capture based on source mode."""
    selected_mode = (mode or "").strip().lower()
    if selected_mode == "pcap":
        yield from read_pcap(
            path=kwargs.get("pcap_path"),
            max_packets=kwargs.get("max_packets"),
        )
        return

    if selected_mode == "live":
        yield from sniff_live(
            interface=kwargs.get("interface"),
            max_packets=kwargs.get("max_packets"),
        )
        return

    raise RuntimeError(f"Unsupported capture mode: {mode}")
