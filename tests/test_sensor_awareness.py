"""Phase 1: sensor-awareness — agent scans must not get scanner-oriented findings."""

from host_doctor.analyzers.auth import analyze_authentication
from host_doctor.analyzers.coverage import analyze_plugin_coverage
from host_doctor.analyzers.network import analyze_network
from host_doctor.analyzers.credential_state import (
    RootCause,
    classify_credential_state,
)
from host_doctor.parsers.nessus import _parse_plugin_19506
from host_doctor.models import HostData, Plugin, ScanConfig, Severity, Vulnerability

AGENT_19506 = """\
Nessus version : 11.2.0
Scan type : Windows Agent
Scan policy used : Advanced Agent Scan
Scanner IP : 127.0.0.1
Credentialed checks : yes
Safe checks : yes
"""

SCANNER_19506 = """\
Nessus version : 11.2.0
Scan type : Normal
Scan policy used : Advanced Network Scan
Scanner IP : 10.0.0.5
Credentialed checks : yes, as 'root' via SSH
"""


def agent_cfg():
    cfg = ScanConfig()
    cfg.sensor_type = "agent"
    return cfg


def make_host(plugin_specs=None, vulns=None, os="Windows Server 2019"):
    plugins = {
        pid: Plugin(pid, f"p{pid}", "Settings", 0, plugin_output=out)
        for pid, out in (plugin_specs or [])
    }
    vulnerabilities = [
        Vulnerability(1000 + i, f"v{i}", fam, 2, port=p)
        for i, (fam, p) in enumerate(vulns or [])
    ]
    return HostData(host_ip="10.0.0.1", operating_system=os,
                    plugins=plugins, vulnerabilities=vulnerabilities)


# --- Parser detection ---------------------------------------------------------

def test_parser_detects_agent_from_scan_type():
    cfg = ScanConfig()
    _parse_plugin_19506(AGENT_19506, cfg)
    assert cfg.sensor_type == "agent"


def test_parser_detects_scanner_from_scan_type():
    cfg = ScanConfig()
    _parse_plugin_19506(SCANNER_19506, cfg)
    assert cfg.sensor_type == "scanner"


def test_parser_loopback_ip_fallback_when_scan_type_absent():
    cfg = ScanConfig()
    _parse_plugin_19506("Scanner IP : 127.0.0.1\nSafe checks : yes\n", cfg)
    assert cfg.sensor_type == "agent"


# --- Agent classification -----------------------------------------------------

def test_agent_with_patch_data_is_success():
    host = make_host(vulns=[("Windows : Microsoft Bulletins", 0)])
    assert classify_credential_state(host, agent_cfg()).root_cause == RootCause.SUCCESS


def test_agent_no_data_is_agent_no_data_not_no_credentials():
    host = make_host()  # no plugins, no patch families
    state = classify_credential_state(host, agent_cfg())
    assert state.root_cause == RootCause.AGENT_NO_DATA
    assert state.root_cause != RootCause.NO_CREDENTIALS_PROVIDED
    assert state.root_cause != RootCause.NETWORK_UNREACHABLE


def test_agent_with_21745_is_local_checks_failed_not_credential_failure():
    host = make_host([(21745, "Local Checks Not Run")])
    state = classify_credential_state(host, agent_cfg())
    assert state.root_cause == RootCause.LOCAL_CHECKS_FAILED_OTHER
    assert state.root_cause != RootCause.CREDENTIAL_FAILURE


def test_agent_no_data_renders_without_keyerror():
    host = make_host()
    findings = analyze_authentication(host, agent_cfg())
    assert any(f.title == "Agent Scan Returned No Assessment Data" for f in findings)
    assert all(isinstance(f.severity, Severity) for f in findings)


# --- Agent suppresses scanner-oriented findings -------------------------------

def test_agent_no_limited_port_finding():
    host = make_host(vulns=[("General", 0)])  # one port -> would trip on a scanner
    titles = [f.title for f in analyze_network(host, agent_cfg())]
    assert "Limited Port Access" not in titles


def test_agent_coverage_suppressed():
    host = make_host([(21745, "Local Checks Not Run")])  # would trip count baseline
    assert analyze_plugin_coverage(host, agent_cfg()) == []


# --- Regression: scanner path unchanged when scan_config absent or scanner ----

def test_scanner_path_unchanged_no_scan_config():
    # No scan_config -> original scanner behavior; 110723 still -> NO_CREDENTIALS.
    host = make_host([(110723, "Protocol : SSH\nNo credentials provided.")])
    assert classify_credential_state(host).root_cause == RootCause.NO_CREDENTIALS_PROVIDED


def test_scanner_sensor_type_still_uses_scanner_logic():
    cfg = ScanConfig()
    cfg.sensor_type = "scanner"
    host = make_host([(104410, "Protocol : SSH\nFailed to authenticate")])
    assert classify_credential_state(host, cfg).root_cause == RootCause.CREDENTIAL_FAILURE


# --- P1 regression: agent scan must never produce a network "Host Unreachable" ---

def test_agent_unreachable_does_not_fire_host_unreachable():
    """An agent scan with is_reachable=False must NOT yield a CRITICAL Host
    Unreachable finding — that would contradict the AGENT_NO_DATA verdict."""
    host = HostData(host_ip="10.0.0.1", operating_system="Windows",
                    plugins={}, vulnerabilities=[], is_reachable=False)
    titles = [f.title for f in analyze_network(host, agent_cfg())]
    assert "Host Unreachable" not in titles
    assert titles == []  # agents get no network/connectivity findings at all
