"""Phase 7a: foundation parsing — distinct max-* settings and policy-preference
extraction for scan-engine/discovery context."""

import xml.etree.ElementTree as ET

from host_doctor.models import ScanConfig
from host_doctor.parsers.nessus import _extract_policy_preferences, _parse_plugin_19506


# --- 19506: max checks vs max hosts no longer conflated -----------------------

def test_max_checks_and_max_hosts_are_distinct():
    cfg = ScanConfig()
    _parse_plugin_19506("Max hosts : 30\nMax checks : 5\n", cfg)
    assert cfg.max_checks_per_host == 5
    assert cfg.max_hosts_per_scan == 30


def test_scanner_ip_stored():
    cfg = ScanConfig()
    _parse_plugin_19506("Scanner IP : 10.0.0.5\n", cfg)
    assert cfg.scanner_ip == "10.0.0.5"


# --- Policy ServerPreferences parsing -----------------------------------------

def _prefs_xml(pairs):
    items = "".join(
        f"<preference><name>{k}</name><value>{v}</value></preference>" for k, v in pairs
    )
    return ET.fromstring(f"<NessusClientData_v2><Policy><Preferences><ServerPreferences>{items}</ServerPreferences></Preferences></Policy></NessusClientData_v2>")


def test_engine_performance_prefs_parsed():
    root = _prefs_xml([
        ("max_hosts", "40"),
        ("max_checks", "4"),
        ("host.max_simult_tcp_sessions", "10"),
        ("max_simult_tcp_sessions", "100"),
        ("reduce_connections_on_congestion", "yes"),
        ("stop_scan_on_disconnect", "no"),
    ])
    cfg = ScanConfig()
    _extract_policy_preferences(root, cfg)
    assert cfg.max_hosts_per_scan == 40
    assert cfg.max_checks_per_host == 4
    assert cfg.max_tcp_sessions_per_host == 10
    assert cfg.max_tcp_sessions_per_scan == 100
    assert cfg.slow_down_on_congestion is True
    assert cfg.stop_when_unresponsive is False


def test_tcp_session_per_host_vs_per_scan_not_conflated():
    root = _prefs_xml([("host.max_simult_tcp_sessions", "8"), ("max_simult_tcp_sessions", "200")])
    cfg = ScanConfig()
    _extract_policy_preferences(root, cfg)
    assert cfg.max_tcp_sessions_per_host == 8
    assert cfg.max_tcp_sessions_per_scan == 200


def test_discovery_methods_and_ports():
    root = _prefs_xml([
        ("icmp_ping", "yes"), ("tcp_ping", "yes"), ("arp_ping", "no"),
        ("tcp_ping_dest_ports", "22,80,443"),
    ])
    cfg = ScanConfig()
    _extract_policy_preferences(root, cfg)
    assert cfg.host_discovery_methods == ["ICMP", "TCP"]
    assert cfg.tcp_ping_ports == [22, 80, 443]


def test_missing_prefs_fail_safe_to_none():
    # No engine/discovery keys -> fields stay None/empty, never fabricated.
    root = _prefs_xml([("TARGET", "10.0.0.1")])
    cfg = ScanConfig()
    _extract_policy_preferences(root, cfg)
    assert cfg.max_tcp_sessions_per_host is None
    assert cfg.scan_unresponsive_hosts is None
    assert cfg.host_discovery_methods == []
