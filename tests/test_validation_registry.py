"""Phase 6b: partial registry access (10428) and pending-reboot validation (35453).

Key properties: partial registry is a softer, distinct cause that is suppressed
when full denial (26917) is also present; the reboot finding is a freshness
caveat that coexists with a successful scan.
"""

from host_doctor.analyzers.auth import analyze_authentication
from host_doctor.analyzers.credential_state import RootCause, classify_credential_state
from host_doctor.analyzers.validation import analyze_validation
from host_doctor.models import HostData, Plugin, ScanConfig, Severity


def make_host(specs, os="Windows Server 2019"):
    return HostData(
        host_ip="10.0.0.1",
        operating_system=os,
        plugins={pid: Plugin(pid, f"p{pid}", "Settings", 0, plugin_output=out) for pid, out in specs},
    )


def causes(state):
    return [i.cause for i in state.additive]


# --- Partial registry: distinct, softer, de-duped behind full denial ----------

def test_partial_registry_is_distinct_cause():
    host = make_host([(117887, "ok"), (10428, "Registry not fully accessible")])
    state = classify_credential_state(host)
    assert RootCause.REGISTRY_PARTIAL_ACCESS in causes(state)
    assert RootCause.REGISTRY_INACCESSIBLE not in causes(state)


def test_partial_registry_is_low_severity():
    host = make_host([(117887, "ok"), (10428, "partial")])
    findings = analyze_authentication(host, ScanConfig())
    f = next(f for f in findings if f.title == "Windows Registry Partially Accessible")
    assert f.severity == Severity.LOW
    assert 10428 in f.plugin_ids
    assert f.evidence


def test_full_denial_supersedes_partial():
    # Both 26917 (full denial) and 10428 (partial) present -> only full denial.
    host = make_host([(117887, "ok"), (26917, "cannot access"), (10428, "partial")])
    state = classify_credential_state(host)
    assert RootCause.REGISTRY_INACCESSIBLE in causes(state)
    assert RootCause.REGISTRY_PARTIAL_ACCESS not in causes(state)


def test_partial_registry_does_not_change_host_verdict():
    host = make_host([(117887, "ok"), (10428, "partial")])
    assert classify_credential_state(host).root_cause == RootCause.SUCCESS


# --- Pending reboot: freshness caveat, coexists with success ------------------

def test_reboot_finding_emitted():
    host = make_host([(35453, "Reboot required")])
    findings = analyze_validation(host, ScanConfig())
    assert len(findings) == 1
    f = findings[0]
    assert f.severity == Severity.MEDIUM
    assert 35453 in f.plugin_ids
    assert "provisional" in " ".join(f.remediation).lower()
    # Names the High remediation angle in the description.
    assert "High" in f.description


def test_no_reboot_no_finding():
    host = make_host([(117887, "ok")])
    assert analyze_validation(host, ScanConfig()) == []
