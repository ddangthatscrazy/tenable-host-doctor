"""Phase 3: 'Limited Port Access' must not blame a firewall when the scan config
or method already explains a low open-port count."""

from host_doctor.analyzers.network import (
    analyze_network,
    _is_narrow_port_range,
    _low_port_count_explained,
)
from host_doctor.models import HostData, Plugin, ScanConfig, Vulnerability


def host_with_one_port(plugins=None):
    return HostData(
        host_ip="10.0.0.1",
        operating_system="Linux",
        plugins={pid: Plugin(pid, f"p{pid}", "Port scanners", 0) for pid in (plugins or [])},
        vulnerabilities=[Vulnerability(1000, "svc", "General", 2, port=443)],
    )


def _titles(host, cfg):
    return [f.title for f in analyze_network(host, cfg)]


# --- Narrow-range detection ---------------------------------------------------

def test_explicit_short_list_is_narrow():
    assert _is_narrow_port_range("21,23,25,80,110") is True


def test_default_is_not_narrow():
    assert _is_narrow_port_range("default") is False


def test_all_is_not_narrow():
    assert _is_narrow_port_range("all") is False


def test_span_is_not_narrow():
    assert _is_narrow_port_range("1-1024") is False


# --- Suppression conditions ---------------------------------------------------

def test_narrow_range_suppresses_limited_port_finding():
    cfg = ScanConfig()
    cfg.port_range = "80,443"
    assert "Limited Port Access" not in _titles(host_with_one_port(), cfg)


def test_local_enumeration_suppresses_limited_port_finding():
    cfg = ScanConfig()
    cfg.port_range = "default"
    # Netstat (SSH) enumeration ran -> low count is genuine, not firewall.
    host = host_with_one_port(plugins=[14272])
    assert "Limited Port Access" not in _titles(host, cfg)


# --- The finding STILL fires when nothing explains it -------------------------

def test_finding_fires_on_broad_scan_with_few_ports():
    cfg = ScanConfig()
    cfg.port_range = "default"  # broad
    # No local enumerator present -> a real network scan found few ports.
    assert "Limited Port Access" in _titles(host_with_one_port(), cfg)


def test_syn_scanner_does_not_suppress():
    # SYN (11219) is a full network port scanner; its presence must NOT suppress.
    cfg = ScanConfig()
    cfg.port_range = "default"
    host = host_with_one_port(plugins=[11219])
    assert "Limited Port Access" in _titles(host, cfg)
