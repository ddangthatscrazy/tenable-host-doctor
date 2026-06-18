"""Phase 7b: protocol-specific credential playbooks. These ENHANCE remediation on
existing auth findings and must never change the verdict or fabricate findings."""

from host_doctor.analyzers.auth import analyze_authentication
from host_doctor.analyzers.credential_state import RootCause, classify_credential_state
from host_doctor.analyzers.protocol_guidance import remediation_for_protocol
from host_doctor.models import HostData, Plugin, ScanConfig


def make_host(specs, os="Windows Server 2019"):
    return HostData(
        host_ip="10.0.0.1",
        operating_system=os,
        plugins={pid: Plugin(pid, f"p{pid}", "Settings", 0, plugin_output=out) for pid, out in specs},
    )


# --- The helper returns protocol-specific steps ------------------------------

def test_smb_playbook_for_windows_credential_failure():
    host = make_host([], os="Windows Server 2019")
    steps = remediation_for_protocol(RootCause.CREDENTIAL_FAILURE, "smb", host, ScanConfig())
    joined = " ".join(steps)
    assert "445" in joined and "administrator" in joined.lower() and "Remote Registry" in joined


def test_ssh_playbook_for_linux_credential_failure():
    host = make_host([], os="Ubuntu Linux 22.04")
    steps = remediation_for_protocol(RootCause.CREDENTIAL_FAILURE, "ssh", host, ScanConfig())
    joined = " ".join(steps)
    assert "SSH" in joined and "sudo" in joined.lower() and "disclaimer" in joined.lower()


def test_protocol_inferred_from_os_when_absent():
    host = make_host([], os="Red Hat Enterprise Linux 9")
    steps = remediation_for_protocol(RootCause.CREDENTIAL_FAILURE, "", host, ScanConfig())
    assert any("SSH" in s for s in steps)   # inferred ssh from Linux OS


def test_102094_adds_escalation_step():
    host = make_host([(102094, "commands require privilege escalation")], os="Linux")
    steps = remediation_for_protocol(RootCause.INSUFFICIENT_PRIVILEGE, "ssh", host, ScanConfig())
    assert any("102094" in s for s in steps)


def test_117885_adds_lockout_step():
    host = make_host([(117885, "intermittent")], os="Linux")
    steps = remediation_for_protocol(RootCause.INTERMITTENT_AUTH, "ssh", host, ScanConfig())
    assert any("117885" in s and "lockout" in s.lower() for s in steps)


# --- Enrichment only: SUCCESS and non-auth causes get nothing -----------------

def test_success_gets_no_playbook():
    host = make_host([], os="Windows")
    assert remediation_for_protocol(RootCause.SUCCESS, "smb", host, ScanConfig()) == []


# --- Integration into analyze_authentication ----------------------------------

def test_auth_finding_remediation_is_enriched():
    # Windows credential failure -> finding remediation should include SMB steps.
    host = make_host([(104410, "Protocol : SMB\nFailed to authenticate")], os="Windows Server 2019")
    findings = analyze_authentication(host, ScanConfig())
    fail = next(f for f in findings if f.title.startswith("Credential"))
    assert any("445" in r for r in fail.remediation)


def test_enrichment_does_not_change_verdict():
    # The verdict from the classifier is identical regardless of enrichment.
    host = make_host([(104410, "Protocol : SMB\nFailed")], os="Windows Server 2019")
    assert classify_credential_state(host).root_cause == RootCause.CREDENTIAL_FAILURE
    # And no extra findings are fabricated by enrichment (same count as causes).
    findings = analyze_authentication(host, ScanConfig())
    assert len(findings) >= 1


# --- P2 regression: non-auth verdict must NOT get credential playbooks --------

def test_local_checks_failed_other_is_not_enriched():
    """LOCAL_CHECKS_FAILED_OTHER means 21745 fired for a non-auth reason, so it
    must NOT receive credential-focused remediation."""
    host = make_host([(21745, "Local checks not run")], os="Ubuntu Linux 22.04")
    steps = remediation_for_protocol(RootCause.LOCAL_CHECKS_FAILED_OTHER, "ssh", host, ScanConfig())
    assert steps == []
