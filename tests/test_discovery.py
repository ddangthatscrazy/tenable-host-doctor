"""Phase 7c: discovery analyzer. Explains network-scan liveness failures, gated
to network scans with no data, and phrases the restrictive case as a possibility."""

from host_doctor.analyzers.discovery import analyze_discovery
from host_doctor.models import HostData, Plugin, ScanConfig, Vulnerability


def unreachable_host(plugins=None):
    return HostData(
        host_ip="10.0.0.1", operating_system="Windows",
        plugins={pid: Plugin(pid, f"p{pid}", "Settings", 0) for pid in (plugins or [])},
        vulnerabilities=[], is_reachable=False,
    )


def reachable_host():
    return HostData(host_ip="10.0.0.1", vulnerabilities=[Vulnerability(1, "v", "General", 2)],
                    is_reachable=True)


def titles(host, cfg):
    return [f.title for f in analyze_discovery(host, cfg)]


# --- Gating -------------------------------------------------------------------

def test_agent_scan_no_discovery_findings():
    cfg = ScanConfig(); cfg.sensor_type = "agent"; cfg.scan_unresponsive_hosts = False
    assert analyze_discovery(unreachable_host(), cfg) == []


def test_reachable_host_no_discovery_findings():
    cfg = ScanConfig(); cfg.scan_unresponsive_hosts = False
    assert analyze_discovery(reachable_host(), cfg) == []


# --- 1. Deterministic: skip-unresponsive-hosts --------------------------------

def test_scan_unresponsive_disabled_fires_deterministic_finding():
    cfg = ScanConfig(); cfg.scan_unresponsive_hosts = False
    f = next(f for f in analyze_discovery(unreachable_host([19506]), cfg)
             if f.title == "Scanner Did Not Continue Assessment After Discovery Failure")
    assert f.confidence == 1.0


def test_scan_unresponsive_unknown_does_not_fire():
    cfg = ScanConfig()  # scan_unresponsive_hosts is None (unparsed) -> fail-safe silent
    assert "Scanner Did Not Continue Assessment After Discovery Failure" not in titles(unreachable_host([19506]), cfg)


# --- 2. Restrictive discovery is a POSSIBILITY, not a verdict ------------------

def test_icmp_only_discovery_is_a_possibility():
    cfg = ScanConfig(); cfg.host_discovery_methods = ["ICMP"]
    f = next(f for f in analyze_discovery(unreachable_host([19506]), cfg)
             if f.title == "Host Discovery May Be Too Restrictive")
    assert f.confidence < 1.0
    assert "lead to check, not a confirmed cause" in f.description


def test_tcp_ping_present_does_not_fire_restrictive():
    cfg = ScanConfig(); cfg.host_discovery_methods = ["ICMP", "TCP"]
    assert "Host Discovery May Be Too Restrictive" not in titles(unreachable_host([19506]), cfg)


def test_no_parsed_methods_fail_safe_silent():
    cfg = ScanConfig()  # host_discovery_methods empty -> restrictive finding never fires
    assert "Host Discovery May Be Too Restrictive" not in titles(unreachable_host([19506]), cfg)


# --- 3. Missing diagnostics ---------------------------------------------------

def test_no_diagnostic_plugins_flags_missing_evidence():
    cfg = ScanConfig()
    assert "Discovery Evidence Missing" in titles(unreachable_host(plugins=[]), cfg)


def test_has_scan_info_no_missing_evidence():
    cfg = ScanConfig()
    assert "Discovery Evidence Missing" not in titles(unreachable_host([19506]), cfg)
