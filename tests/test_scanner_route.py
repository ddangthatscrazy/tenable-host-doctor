"""Phase 7d: restrained scanner-route analyzer. Latency requires a corroborating
symptom; load is a fidelity lead. No speculative zone-guessing exists to test."""

from host_doctor.analyzers.scanner_route import analyze_scanner_route
from host_doctor.models import HostData, Plugin, ScanConfig


def host(duration=None, plugins=None):
    return HostData(
        host_ip="10.0.0.1",
        scan_duration_seconds=duration,
        plugins={pid: Plugin(pid, f"p{pid}", "Settings", 0) for pid in (plugins or [])},
    )


def titles(h, cfg):
    return [f.title for f in analyze_scanner_route(h, cfg)]


# --- Latency requires a corroborating symptom ---------------------------------

def test_high_latency_alone_does_not_fire():
    cfg = ScanConfig(); cfg.ping_rtt_ms = 250.0  # high RTT but no slowness/timeout symptom
    assert "High Scanner-to-Target Latency" not in titles(host(duration=120), cfg)


def test_high_latency_with_slow_scan_fires():
    cfg = ScanConfig(); cfg.ping_rtt_ms = 250.0
    f = next(f for f in analyze_scanner_route(host(duration=1200), cfg)
             if f.title == "High Scanner-to-Target Latency")
    assert f.confidence < 1.0


def test_low_latency_never_fires():
    cfg = ScanConfig(); cfg.ping_rtt_ms = 5.0
    assert "High Scanner-to-Target Latency" not in titles(host(duration=1200), cfg)


def test_missing_rtt_fail_safe():
    cfg = ScanConfig()  # ping_rtt_ms None (e.g. "Unavailable") -> no latency finding
    assert "High Scanner-to-Target Latency" not in titles(host(duration=1200), cfg)


def test_firewall_folded_as_evidence_not_standalone():
    cfg = ScanConfig(); cfg.ping_rtt_ms = 250.0
    findings = analyze_scanner_route(host(duration=1200, plugins=[27576]), cfg)
    # 27576 is corroborating evidence on the latency finding, never its own finding.
    assert "Network Middlebox" not in " ".join(t for t in titles(host(duration=1200, plugins=[27576]), cfg))
    lat = next(f for f in findings if f.title == "High Scanner-to-Target Latency")
    assert any("27576" in e for e in lat.evidence)


# --- Scanner load: high concurrency on a slow scan ----------------------------

def test_scanner_load_fires_on_high_concurrency_slow_scan():
    cfg = ScanConfig(); cfg.max_checks_per_host = 15
    f = next(f for f in analyze_scanner_route(host(duration=1200), cfg)
             if f.title == "Scanner Load May Be Affecting Result Fidelity")
    assert f.confidence < 1.0


def test_scanner_load_quiet_on_fast_scan():
    cfg = ScanConfig(); cfg.max_checks_per_host = 15
    assert "Scanner Load May Be Affecting Result Fidelity" not in titles(host(duration=120), cfg)


def test_scanner_load_quiet_on_normal_concurrency():
    cfg = ScanConfig(); cfg.max_checks_per_host = 5  # default-ish
    assert "Scanner Load May Be Affecting Result Fidelity" not in titles(host(duration=1200), cfg)


# --- Agent scans are excluded -------------------------------------------------

def test_agent_scan_excluded():
    cfg = ScanConfig(); cfg.sensor_type = "agent"; cfg.ping_rtt_ms = 250.0
    assert analyze_scanner_route(host(duration=1200), cfg) == []
