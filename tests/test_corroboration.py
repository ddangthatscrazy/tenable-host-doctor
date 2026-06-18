"""Phase 6c: corroboration signals. These must STRENGTHEN existing verdicts and
add evidence — never create standalone findings, and (critically) integration
success must never satisfy host any_success.
"""

from host_doctor.analyzers.correlation import (
    INTEGRATION_SUCCESS_PLUGINS,
    SSH_AUTH_SUCCESS_PLUGINS,
    WINDOWS_AUTH_SUCCESS_PLUGINS,
    check_any_auth_success,
    check_ssh_auth_success,
    check_windows_auth_success,
)
from host_doctor.analyzers.network import analyze_network
from host_doctor.models import HostData, Plugin, ScanConfig, Vulnerability


def host(pids, vulns=None):
    return HostData(
        host_ip="10.0.0.1",
        plugins={pid: Plugin(pid, f"p{pid}", "Settings", 0) for pid in pids},
        vulnerabilities=[Vulnerability(1000 + i, f"v{i}", "General", 2, port=p) for i, p in enumerate(vulns or [])],
    )


# --- Windows / SSH corroboration ----------------------------------------------

def test_wmi_available_corroborates_windows_success():
    assert 24269 in WINDOWS_AUTH_SUCCESS_PLUGINS
    assert check_windows_auth_success(host([24269]))["success"] is True


def test_registry_remotely_accessible_corroborates_windows():
    assert 10400 in WINDOWS_AUTH_SUCCESS_PLUGINS
    assert check_windows_auth_success(host([10400]))["success"] is True


def test_ssh_software_enum_corroborates_ssh_success():
    assert 22869 in SSH_AUTH_SUCCESS_PLUGINS
    assert check_ssh_auth_success(host([22869]))["success"] is True


# --- 12634 label fix ----------------------------------------------------------

def test_12634_label_corrected():
    assert SSH_AUTH_SUCCESS_PLUGINS[12634] == "Authenticated Check: OS Name and Installed Package Enumeration"


# --- The structural soundness property: integration success != host success ----

def test_integration_success_is_separate_dimension():
    assert 122502 in INTEGRATION_SUCCESS_PLUGINS


def test_integration_login_alone_does_not_satisfy_host_auth():
    # ONLY a patch-management login succeeded (122502), no host auth signals.
    result = check_any_auth_success(host([122502]))
    assert result["integration_success"] is True
    assert result["any_success"] is False   # must NOT mask a host credential failure


def test_host_success_still_works_independently():
    result = check_any_auth_success(host([117887]))  # authoritative host success
    assert result["any_success"] is True


# --- 27576 is context-only, never a standalone finding ------------------------

def test_firewall_detection_adds_context_not_a_finding():
    # Limited Port Access fires (1 open port, broad scan); 27576 should ride along
    # as evidence, not produce a separate finding.
    h = host([27576], vulns=[443])
    cfg = ScanConfig()
    cfg.port_range = "default"
    findings = analyze_network(h, cfg)
    titles = [f.title for f in findings]
    assert titles.count("Limited Port Access") == 1
    assert "Firewall Detection" not in titles  # no standalone finding
    lpa = next(f for f in findings if f.title == "Limited Port Access")
    assert any("27576" in e for e in lpa.evidence)
    assert 27576 in lpa.plugin_ids


def test_no_firewall_plugin_no_context():
    h = host([], vulns=[443])
    cfg = ScanConfig()
    cfg.port_range = "default"
    lpa = next(f for f in analyze_network(h, cfg) if f.title == "Limited Port Access")
    assert not any("27576" in e for e in lpa.evidence)
