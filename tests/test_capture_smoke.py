from pathlib import Path

from ids.capture import read_pcap
from ids.features import extract_features


def test_read_pcap_yields_packet_summary():
    sample_pcap = Path("data/raw/sample.pcap")

    rows = list(read_pcap(str(sample_pcap), max_packets=1))

    assert len(rows) == 1
    row = rows[0]
    assert {"timestamp", "src_ip", "dst_ip", "protocol", "packet_length"}.issubset(
        row.keys()
    )


def test_extract_features_from_pcap_summary():
    sample_pcap = Path("data/raw/sample.pcap")

    rows = list(read_pcap(str(sample_pcap), max_packets=1))
    features = extract_features(rows[0])

    assert features is not None
    assert features["protocol_number"] == 6
    assert features["protocol_name"] == "TCP"
    assert features["src_port"] == 12345
    assert features["dst_port"] == 80
