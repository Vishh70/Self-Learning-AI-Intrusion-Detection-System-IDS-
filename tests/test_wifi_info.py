from ids.capture import detect_connected_ssid


def test_detect_connected_ssid_returns_string_or_none():
    ssid, bssid = detect_connected_ssid("WiFi")
    assert ssid is None or isinstance(ssid, str)
    assert bssid is None or isinstance(bssid, str)
