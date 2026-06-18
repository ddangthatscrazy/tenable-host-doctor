"""Protocol-specific credential playbooks.

This is pure remediation ENRICHMENT: given an existing auth verdict and the
protocol it concerns, it returns additional, concrete next-step checks (SMB/WMI,
SSH, or database). It never changes the verdict and never emits a finding — it
only makes the remediation on findings that already exist more actionable.
Returns [] whenever no protocol-specific guidance applies.
"""

from host_doctor.analyzers.credential_state import RootCause
from host_doctor.models import HostData, ScanConfig

# Auth-problem verdicts where protocol-specific next steps add value.
# NOTE: LOCAL_CHECKS_FAILED_OTHER is deliberately excluded — the classifier assigns
# it precisely when 21745 fired for a NON-auth, non-socket reason, so attaching
# credential next-steps would contradict the verdict's own conclusion.
_ENRICHABLE = {
    RootCause.CREDENTIAL_FAILURE,
    RootCause.NO_CREDENTIALS_PROVIDED,
    RootCause.INSUFFICIENT_PRIVILEGE,
    RootCause.REGISTRY_INACCESSIBLE,
    RootCause.REGISTRY_PARTIAL_ACCESS,
    RootCause.INTERMITTENT_AUTH,
    RootCause.DATABASE_AUTH_FAILURE,
}

P_SSH_PRIV_ESCALATION = 102094  # SSH commands require privilege escalation
P_INTERMITTENT = 117885         # Intermittent authentication failure


def _infer_protocol(protocol: str, host_data: HostData) -> str:
    """Use the explicit protocol if known; otherwise infer from the OS."""
    if protocol in ("ssh", "smb", "database", "integration"):
        return protocol
    os_str = (host_data.operating_system or "").lower()
    if "windows" in os_str:
        return "smb"
    if any(x in os_str for x in ("linux", "unix", "bsd", "aix", "solaris", "mac os", "darwin")):
        return "ssh"
    return ""


def remediation_for_protocol(
    cause: RootCause,
    protocol: str,
    host_data: HostData,
    scan_config: ScanConfig,
) -> list[str]:
    """Return protocol-specific next-step checks to append to a finding's
    remediation. Enrichment only — returns [] when nothing protocol-specific
    applies, so it can never alter or fabricate a verdict."""
    if cause not in _ENRICHABLE:
        return []

    proto = _infer_protocol(protocol, host_data)
    steps: list[str] = []

    if proto == "smb":
        steps += [
            "SMB/WMI: confirm TCP/445 is reachable from the scanner to the target.",
            "Verify the scan account has local administrator rights on the target.",
            "Ensure the Remote Registry service is running (required for registry-based checks).",
            "Check Windows Firewall allows File and Printer Sharing, Remote Service Management, and WMI.",
            "If using a local account, check UAC remote-token filtering (LocalAccountTokenFilterPolicy=1).",
            "Prefer a domain or dedicated scan account with the least required privilege.",
        ]
    elif proto == "ssh":
        steps += [
            "SSH: confirm the SSH port is reachable and the handshake/banner completes from the scanner.",
            "Verify the password or private key is valid for the scan account.",
            "Check sudo/su privilege escalation is configured if elevated checks are needed.",
        ]
        if host_data.has_plugin(P_SSH_PRIV_ESCALATION):
            steps.append(
                f"Plugin {P_SSH_PRIV_ESCALATION} indicates SSH commands need privilege escalation — "
                "configure sudo/su and add the required commands to sudoers."
            )
        if host_data.has_plugin(P_INTERMITTENT):
            steps.append(
                f"Plugin {P_INTERMITTENT} indicates intermittent auth — check for rate limiting or "
                "account lockout triggered by repeated logins."
            )
        steps.append(
            "If the target presents an SSH login banner/disclaimer (e.g. FortiOS), enable the "
            "policy's 'Automatically accept detected SSH disclaimer prompts' setting."
        )
    elif proto == "database":
        steps += [
            "Database: confirm the DB listener port is reachable from the scanner.",
            "Verify the DB username, password, and service/SID, and that the account may connect "
            "from the scanner host.",
        ]

    return steps
