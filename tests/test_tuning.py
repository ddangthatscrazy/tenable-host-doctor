"""Phase 5: scan-tuning analyzer — advise on a slow scan, stay quiet on a fast one."""

from host_doctor.analyzers.tuning import analyze_scan_tuning, SLOW_SCAN_SECONDS
from host_doctor.models import HostData, ScanConfig, Vulnerability


def host(duration=None, vulns=None):
    return HostData(
        host_ip="10.0.0.1",
        scan_duration_seconds=duration,
        vulnerabilities=[Vulnerability(1000 + i, f"v{i}", fam, 2) for i, fam in enumerate(vulns or [])],
    )


def slow():
    return host(duration=SLOW_SCAN_SECONDS + 100)


def _titles(h, cfg):
    return [f.title for f in analyze_scan_tuning(h, cfg)]


# --- Gating on duration -------------------------------------------------------

def test_fast_scan_is_quiet():
    cfg = ScanConfig()
    cfg.thorough_tests = True
    assert analyze_scan_tuning(host(duration=120), cfg) == []  # 2 min -> quiet


def test_unknown_duration_still_advises():
    cfg = ScanConfig()
    cfg.thorough_tests = True
    assert "Thorough Tests Enabled" in _titles(host(duration=None), cfg)


# --- Individual settings on a slow scan ---------------------------------------

def test_thorough_tests_flagged_when_slow():
    cfg = ScanConfig()
    cfg.thorough_tests = True
    assert "Thorough Tests Enabled" in _titles(slow(), cfg)


def test_elevated_timeout_flagged():
    cfg = ScanConfig()
    cfg.network_timeout = 60
    assert "Elevated Network Timeout" in _titles(slow(), cfg)


def test_normal_timeout_not_flagged():
    cfg = ScanConfig()
    cfg.network_timeout = 5
    assert "Elevated Network Timeout" not in _titles(slow(), cfg)


def test_optimize_off_flagged():
    cfg = ScanConfig()
    cfg.optimize_tests = False
    assert "Test Optimization Disabled" in _titles(slow(), cfg)


def test_optimize_on_not_flagged():
    cfg = ScanConfig()
    cfg.optimize_tests = True
    assert "Test Optimization Disabled" not in _titles(slow(), cfg)


def test_udp_flagged_for_scanner():
    cfg = ScanConfig()
    cfg.port_range = "T:1-1024,U:300-500"
    assert "UDP Port Scanning Enabled" in _titles(slow(), cfg)


def test_udp_not_flagged_for_agent():
    cfg = ScanConfig()
    cfg.sensor_type = "agent"
    cfg.port_range = "T:1-1024,U:300-500"
    assert "UDP Port Scanning Enabled" not in _titles(slow(), cfg)


# --- Compliance phrased for file-content, only when slow ----------------------

def test_compliance_flagged_when_slow():
    cfg = ScanConfig()
    h = slow()
    h.vulnerabilities.append(Vulnerability(99999, "audit", "Policy Compliance", 0))
    titles = _titles(h, cfg)
    assert "Compliance Auditing Present on a Slow Scan" in titles


def test_compliance_not_flagged_when_fast():
    cfg = ScanConfig()
    h = host(duration=100, vulns=["Policy Compliance"])
    assert analyze_scan_tuning(h, cfg) == []


# --- Nothing set -> nothing emitted -------------------------------------------

def test_clean_config_no_findings():
    assert analyze_scan_tuning(slow(), ScanConfig()) == []
