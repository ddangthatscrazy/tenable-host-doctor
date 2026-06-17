"""Tests for the credential-state classifier and the auth analyzer.

Focus is on the two false-positive traps the refactor fixes:
  1. plugin 21745 (socket error) must NOT be reported as a credential failure
  2. plugin 102094 (SSH priv-escalation) must NOT be reported as auth success
"""

from host_doctor.analyzers.auth import analyze_authentication
from host_doctor.analyzers.coverage import analyze_plugin_coverage
from host_doctor.analyzers.credential_state import (
    RootCause,
    classify_credential_state,
)
from host_doctor.models import (
    HostData,
    Plugin,
    ScanConfig,
    Severity,
    Vulnerability,
)


def make_host(plugin_specs=None, vulns=None, reachable=True, os="Linux Kernel 5.4"):
    """Build a HostData with the given plugins.

    plugin_specs: iterable of (plugin_id, output) tuples.
    vulns: iterable of family names to attach as Vulnerability rows.
    """
    plugins = {}
    for pid, output in (plugin_specs or []):
        plugins[pid] = Plugin(
            plugin_id=pid, plugin_name=f"plugin-{pid}", family="Settings",
            severity=0, plugin_output=output,
        )
    vulnerabilities = [
        Vulnerability(plugin_id=1000 + i, plugin_name=f"v{i}", family=fam, severity=2)
        for i, fam in enumerate(vulns or [])
    ]
    return HostData(
        host_ip="192.168.1.100", operating_system=os,
        plugins=plugins, vulnerabilities=vulnerabilities, is_reachable=reachable,
    )


SCAN = ScanConfig(has_ssh_creds=True, credential_used="root", credential_protocol="SSH")


# --- The core bug: 21745 socket error is connectivity, not credentials --------

def test_21745_socket_error_is_connectivity_not_credentials():
    host = make_host([
        (21745, "Local Checks Not Run\nUnable to create a socket on port 445."),
    ])
    state = classify_credential_state(host)
    assert state.root_cause == RootCause.CONNECTIVITY_DURING_AUTH
    assert state.root_cause != RootCause.CREDENTIAL_FAILURE


def test_21745_with_104410_is_a_real_credential_failure():
    host = make_host([
        (21745, "Local Checks Not Run"),
        (104410, "Protocol : SSH\nPort : 22\nFailed to authenticate using the supplied password"),
    ])
    state = classify_credential_state(host)
    assert state.root_cause == RootCause.CREDENTIAL_FAILURE
    assert state.protocol == "ssh"


# --- The other bug: 102094 is priv-escalation, never a success signal ---------

def test_102094_is_insufficient_privilege_not_success():
    host = make_host([
        (P := 102094, "The following commands require privilege escalation: rpm -qa"),
        (21745, "Local Checks Not Run"),
    ])
    state = classify_credential_state(host)
    assert RootCause.INSUFFICIENT_PRIVILEGE in state.additive
    assert state.root_cause != RootCause.SUCCESS


# --- Authoritative success / no-creds / intermittent --------------------------

def test_117887_means_success():
    host = make_host([(117887, "Local security checks have been enabled.")])
    assert classify_credential_state(host).root_cause == RootCause.SUCCESS


def test_patch_families_mean_success_without_117887():
    host = make_host(vulns=["Ubuntu Local Security Checks", "Ubuntu Local Security Checks"])
    assert classify_credential_state(host).root_cause == RootCause.SUCCESS


def test_110723_means_no_credentials_provided():
    host = make_host([(110723, "Protocol : SSH\nNo credentials were provided.")])
    state = classify_credential_state(host)
    assert state.root_cause == RootCause.NO_CREDENTIALS_PROVIDED


def test_117885_means_intermittent():
    host = make_host([(117885, "Protocol : SMB\nIntermittent authentication failure.")])
    assert classify_credential_state(host).root_cause == RootCause.INTERMITTENT_AUTH


def test_unreachable_host():
    # Genuinely unreachable: parser flagged it down AND no response evidence at all.
    host = make_host([], reachable=False)
    assert classify_credential_state(host).root_cause == RootCause.NETWORK_UNREACHABLE


def test_ping_reply_present_is_not_unreachable():
    # Plugin 10180 firing means the host DID respond to discovery, so even with
    # is_reachable=False it must not be classified as unreachable. With no auth
    # signals it falls through to INDETERMINATE.
    host = make_host([(10180, "The remote host is up.")], reachable=False)
    assert classify_credential_state(host).root_cause != RootCause.NETWORK_UNREACHABLE


def test_indeterminate_when_no_signals():
    host = make_host([(19506, "Nessus Scan Information")])
    state = classify_credential_state(host)
    assert state.root_cause == RootCause.INDETERMINATE
    assert state.confidence < 0.5


# --- Precedence: success beats everything; additive coexists ------------------

def test_success_with_registry_additive():
    host = make_host([
        (117887, "Local security checks have been enabled."),
        (26917, "Could not connect to the registry."),
    ], os="Windows Server 2019")
    state = classify_credential_state(host)
    assert state.root_cause == RootCause.SUCCESS
    assert RootCause.REGISTRY_INACCESSIBLE in state.additive


# --- Analyzer wiring: severities + no double-critical with coverage -----------

def test_credential_failure_emits_critical_finding():
    host = make_host([
        (21745, "Local Checks Not Run"),
        (104410, "Protocol : SSH\nFailed to authenticate using the supplied password"),
    ])
    findings = analyze_authentication(host, SCAN)
    assert any(f.severity == Severity.CRITICAL for f in findings)


def test_connectivity_finding_is_not_critical_credentials():
    host = make_host([(21745, "Local Checks Not Run\nUnable to connect.")])
    findings = analyze_authentication(host, SCAN)
    titles = " ".join(f.title for f in findings).lower()
    assert "connectivity" in titles
    assert "credential authentication failed" not in titles


def test_coverage_suppressed_on_authenticated_success():
    # Sparse plugin count but local checks ran -> no false "low coverage" finding.
    host = make_host([(117887, "Local security checks have been enabled.")])
    assert analyze_plugin_coverage(host, SCAN) == []
