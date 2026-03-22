from ids.features import extract_features, extract_protocol_name, is_private_ip


def test_extract_protocol_name_maps_common_protocols():
    assert extract_protocol_name(6) == "TCP"
    assert extract_protocol_name(17) == "UDP"
    assert extract_protocol_name(1) == "ICMP"
    assert extract_protocol_name(99) == "OTHER"


def test_is_private_ip_handles_private_and_public_addresses():
    assert is_private_ip("192.168.1.10") == 1
    assert is_private_ip("8.8.8.8") == 0
    assert is_private_ip("not-an-ip") == 0


def test_extract_features_fills_defaults_for_missing_transport_fields():
    packet_summary = {
        "timestamp": "2026-03-22T10:15:00",
        "src_ip": "10.0.0.5",
        "dst_ip": "8.8.8.8",
        "protocol": 1,
        "packet_length": 84,
    }

    features = extract_features(packet_summary)

    assert features is not None
    assert features["src_port"] == 0
    assert features["dst_port"] == 0
    assert features["ttl"] == 0
    assert features["tcp_flags"] == ""
    assert features["has_payload"] == 0
    assert features["is_icmp"] == 1


def test_extract_features_sets_transport_indicators():
    packet_summary = {
        "timestamp": "2026-03-22T10:15:00",
        "src_ip": "192.168.1.10",
        "dst_ip": "8.8.8.8",
        "protocol": 6,
        "packet_length": 74,
        "ttl": 64,
        "src_port": 12345,
        "dst_port": 80,
        "tcp_flags": "S",
        "has_payload": 1,
    }

    features = extract_features(packet_summary)

    assert features is not None
    assert features["protocol_name"] == "TCP"
    assert features["is_tcp"] == 1
    assert features["is_udp"] == 0
    assert features["src_is_private"] == 1
    assert features["dst_is_private"] == 0
    assert features["tcp_flags"] == "S"
    assert features["has_payload"] == 1
