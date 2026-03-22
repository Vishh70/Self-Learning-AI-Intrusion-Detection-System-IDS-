from ids.capture import detect_active_interface, resolve_live_interface


def test_resolve_live_interface_prefers_explicit_name():
    assert resolve_live_interface("WiFi") == "WiFi"


def test_detect_active_interface_returns_string_or_none():
    detected = detect_active_interface()
    assert detected is None or isinstance(detected, str)
