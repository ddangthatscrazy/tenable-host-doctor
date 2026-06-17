"""Authentication analyzer — emits Findings from the credential-state classifier.

This module no longer derives auth verdicts inline. It delegates to
``classify_credential_state`` (the single source of truth) and renders the
resulting verdict + additive issues into Finding objects. That removes the old
bug where plugin 21745 ("Local Checks Not Run") was treated as an SMB
credential failure, which misdiagnosed connectivity/socket problems as bad
credentials.
"""

from host_doctor.analyzers.credential_state import (
    CredentialState,
    RootCause,
    classify_credential_state,
)
from host_doctor.models import Finding, FindingCategory, HostData, ScanConfig, Severity

# --- Verdict -> presentation maps --------------------------------------------

_SEVERITY: dict[RootCause, Severity] = {
    RootCause.SUCCESS: Severity.INFO,
    RootCause.NO_CREDENTIALS_PROVIDED: Severity.HIGH,
    RootCause.CREDENTIAL_FAILURE: Severity.CRITICAL,
    RootCause.INTERMITTENT_AUTH: Severity.HIGH,
    RootCause.CONNECTIVITY_DURING_AUTH: Severity.HIGH,
    RootCause.NETWORK_UNREACHABLE: Severity.CRITICAL,
    RootCause.INSUFFICIENT_PRIVILEGE: Severity.MEDIUM,
    RootCause.REGISTRY_INACCESSIBLE: Severity.MEDIUM,
    RootCause.LOCAL_CHECKS_FAILED_OTHER: Severity.HIGH,
    RootCause.INDETERMINATE: Severity.MEDIUM,
}

_TITLE: dict[RootCause, str] = {
    RootCause.SUCCESS: "Credentialed Assessment Succeeded",
    RootCause.NO_CREDENTIALS_PROVIDED: "No Credentials Provided",
    RootCause.CREDENTIAL_FAILURE: "Credential Authentication Failed",
    RootCause.INTERMITTENT_AUTH: "Intermittent Authentication Failure",
    RootCause.CONNECTIVITY_DURING_AUTH: "Local Checks Failed — Connectivity, Not Credentials",
    RootCause.NETWORK_UNREACHABLE: "Host Unreachable",
    RootCause.INSUFFICIENT_PRIVILEGE: "Authenticated but Under-Privileged",
    RootCause.REGISTRY_INACCESSIBLE: "Windows Registry Access Denied",
    RootCause.LOCAL_CHECKS_FAILED_OTHER: "Local Checks Did Not Run",
    RootCause.INDETERMINATE: "Authentication Status Indeterminate",
}

_DESCRIPTION: dict[RootCause, str] = {
    RootCause.SUCCESS: "Credentialed local checks ran on this host; the scan is properly authenticated.",
    RootCause.NO_CREDENTIALS_PROVIDED: (
        "Ports usable for local checks were found, but no credentials were attached to the scan. "
        "This is a configuration gap, not an authentication failure."
    ),
    RootCause.CREDENTIAL_FAILURE: "Credentials were provided but authentication failed for this host.",
    RootCause.INTERMITTENT_AUTH: (
        "Authentication succeeded at least once but then failed on subsequent attempts — typically "
        "account lockout, device rate limiting, or an unstable connection."
    ),
    RootCause.CONNECTIVITY_DURING_AUTH: (
        "Local checks did not run, but the underlying cause is a network/socket failure rather than "
        "bad credentials. Plugin 21745 fired without a corroborating credential-failure plugin (104410)."
    ),
    RootCause.NETWORK_UNREACHABLE: "The host did not respond to assessment; only connectivity plugins fired.",
    RootCause.INSUFFICIENT_PRIVILEGE: (
        "Authentication succeeded, but the account lacked the privilege needed for some checks, so "
        "results are incomplete."
    ),
    RootCause.REGISTRY_INACCESSIBLE: (
        "Nessus authenticated but could not access the Windows registry, so registry-based checks and "
        "patch assessment are incomplete."
    ),
    RootCause.LOCAL_CHECKS_FAILED_OTHER: (
        "Local checks did not run for a reason that is neither a credential failure nor a socket error. "
        "Inspect the plugin 21745 body for the specific cause."
    ),
    RootCause.INDETERMINATE: (
        "There is not enough evidence to determine authentication status. The credential-status plugins "
        "are absent, which usually means plugin debugging was off or the export is sparse."
    ),
}

_REMEDIATION: dict[RootCause, list[str]] = {
    RootCause.SUCCESS: [],
    RootCause.NO_CREDENTIALS_PROVIDED: [
        "Attach a managed credential of the correct type (SSH for *nix, Windows for SMB/WMI) to the scan.",
        "Confirm the credential is assigned to THIS scan, not merely stored in the credential vault.",
    ],
    RootCause.CREDENTIAL_FAILURE: [
        "Verify the credential's username and secret directly against the target.",
        "Windows: confirm local-vs-domain form (CORP\\user or user@corp.local vs WORKGROUP\\user).",
        "SSH: confirm key passphrase and that the key type/algorithm is accepted by sshd_config.",
        "Check for account lockout if the scan ran repeatedly against this host.",
    ],
    RootCause.INTERMITTENT_AUTH: [
        "Check account lockout thresholds — parallel logins during a scan can trip them.",
        "Reduce max checks per host / scan concurrency.",
        "Investigate device rate limiting (SSH plugin 122501).",
    ],
    RootCause.CONNECTIVITY_DURING_AUTH: [
        "Treat this as a NETWORK issue, not credentials — do not rotate credentials.",
        "Verify scanner-to-host reachability on the authentication port (445 for SMB, 22 for SSH).",
        "Check firewall / security-group rules and scanner zone placement.",
        "Check socket / open-file limits on the scanner (nessusd.messages, nessusd.dump).",
    ],
    RootCause.NETWORK_UNREACHABLE: [
        "Confirm the host is up and reachable from the scanner's network zone.",
        "Review host-discovery settings and intervening firewalls.",
    ],
    RootCause.INSUFFICIENT_PRIVILEGE: [
        "Windows: grant the scan account local administrator on the target.",
        "SSH: configure privilege escalation (sudo/su) in the credential; add required commands to sudoers.",
        "Re-run and confirm plugin 102094 (SSH) / 24786 (Windows) no longer reports failures.",
    ],
    RootCause.REGISTRY_INACCESSIBLE: [
        "Enable and start the Remote Registry service on the target.",
        "Set LocalAccountTokenFilterPolicy=1 if using a local admin account (UAC remote-token filtering).",
        "Confirm no GPO blocks remote registry access.",
    ],
    RootCause.LOCAL_CHECKS_FAILED_OTHER: [
        "Inspect the plugin 21745 body for the specific error.",
        "Confirm the OS is supported for local checks and the plugin feed is current.",
    ],
    RootCause.INDETERMINATE: [
        "Re-run with plugin debugging enabled to populate plugin 84239 and the credential-status family.",
        "Use the diagnostic scan generator to produce a policy with debug logging on.",
    ],
}


def _maybe_protocol(title: str, protocol: str) -> str:
    if protocol:
        return f"{title} ({protocol.upper()})"
    return title


def _finding_for(cause: RootCause, state: CredentialState, *, primary: bool) -> Finding:
    evidence = list(state.evidence) if primary else []
    return Finding(
        category=FindingCategory.AUTHENTICATION,
        severity=_SEVERITY[cause],
        title=_maybe_protocol(_TITLE[cause], state.protocol if primary else ""),
        description=_DESCRIPTION[cause],
        evidence=evidence,
        remediation=_REMEDIATION[cause],
        plugin_ids=sorted(set(state.plugin_ids)) if primary else [],
        confidence=state.confidence if primary else 1.0,
    )


def analyze_authentication(host_data: HostData, scan_config: ScanConfig) -> list[Finding]:
    """Analyze authentication status via the credential-state classifier.

    Returns a primary verdict finding (unless the host fully succeeded with no
    caveats) plus additive findings for privilege/registry issues that can
    coexist with success.
    """
    state = classify_credential_state(host_data)
    findings: list[Finding] = []

    # Primary verdict. Suppress the INFO "succeeded" finding when clean, but keep
    # it if there are additive caveats so the report explains the partial result.
    if state.root_cause != RootCause.SUCCESS or state.additive:
        findings.append(_finding_for(state.root_cause, state, primary=True))

    # Additive privilege/registry findings (can coexist with SUCCESS).
    for extra in state.additive:
        findings.append(_finding_for(extra, state, primary=False))

    return findings
