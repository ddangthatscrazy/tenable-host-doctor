"""Phase 2: the diagnostic scan generator must default to safe checks ON."""

from host_doctor.scan_creator import create_diagnostic_scan_config


def test_safe_checks_on_by_default():
    cfg = create_diagnostic_scan_config(host="192.168.1.100")
    assert cfg["settings"]["safe_checks"] is True


def test_unsafe_flag_disables_safe_checks():
    cfg = create_diagnostic_scan_config(host="192.168.1.100", unsafe=True)
    assert cfg["settings"]["safe_checks"] is False


def test_unsafe_default_is_false():
    # Explicitly passing unsafe=False keeps safe checks on.
    cfg = create_diagnostic_scan_config(host="192.168.1.100", unsafe=False)
    assert cfg["settings"]["safe_checks"] is True


def test_debug_still_honored_independently():
    cfg = create_diagnostic_scan_config(host="192.168.1.100", enable_debug=False, unsafe=True)
    assert cfg["settings"]["plugin_debugging"] is False
    assert cfg["settings"]["safe_checks"] is False
