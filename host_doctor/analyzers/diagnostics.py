"""Diagnostics analyzer — detect when scan lacks plugin debugging data."""

from host_doctor.analyzers.correlation import check_any_auth_success
from host_doctor.models import Finding, FindingCategory, HostData, ScanConfig, Severity

# Plugin 84239 is present only when plugin debugging is enabled in the scan policy.
_DEBUG_LOG_PLUGIN_ID = 84239


def should_recommend_debug_scan(
    host_data: HostData,
    scan_config: ScanConfig,
    findings: list[Finding],
) -> bool:
    """Return True when enabling debug logging would yield actionable new data.

    Conditions (any one is sufficient):
    - Credentials were configured but auth did not succeed
    - Other analyzers already produced auth or high-severity policy findings
    """
    # Already have debug data — no recommendation needed
    if host_data.has_plugin(_DEBUG_LOG_PLUGIN_ID):
        return False
    if scan_config.debugging_enabled is True:
        return False

    # Only flag auth failure when credentials were actually configured —
    # an empty host with no creds has nothing to debug.
    has_creds = scan_config.has_ssh_creds or scan_config.has_windows_creds or scan_config.has_snmp_creds
    if has_creds:
        auth_result = check_any_auth_success(host_data)
        if not auth_result.get("any_success", False):
            return True

    # Also recommend if other analyzers already surfaced auth or policy issues
    has_relevant_finding = any(
        f.category == FindingCategory.AUTHENTICATION
        or (f.category == FindingCategory.POLICY and f.severity.value in ("high", "critical"))
        for f in findings
    )

    return has_relevant_finding


def detect_missing_debug_data(
    host_data: HostData,
    scan_config: ScanConfig,
    findings: list[Finding] | None = None,
) -> list[Finding]:
    """Return a finding when debug logging was off and it would help diagnosis.

    Args:
        host_data: Parsed host scan data
        scan_config: Parsed scan configuration
        findings: Findings already produced by other analyzers (used to determine
                  whether debug data would actually add value). Pass an empty list
                  or None if calling before other analyzers have run.

    Returns:
        A single-element list with a MISSING_DIAGNOSTICS finding, or an empty list.
    """
    if findings is None:
        findings = []

    # Always flag if debugging is explicitly off or unknown AND 84239 is absent —
    # let should_recommend_debug_scan decide whether it would actually help.
    if host_data.has_plugin(_DEBUG_LOG_PLUGIN_ID):
        return []

    if scan_config.debugging_enabled is True:
        return []

    # Only recommend if there's something worth diagnosing
    if not should_recommend_debug_scan(host_data, scan_config, findings):
        return []

    debugging_status = (
        "Explicitly disabled" if scan_config.debugging_enabled is False
        else "Not detected (plugin 84239 absent)"
    )

    finding = Finding(
        category=FindingCategory.MISSING_DIAGNOSTICS,
        severity=Severity.MEDIUM,
        title="Plugin Debugging Not Enabled",
        description=(
            "This scan does not have plugin debugging enabled. Without it, Host Doctor "
            "can identify that authentication likely failed but cannot see the exact SSH "
            "commands attempted, detailed error codes, or which credential steps failed. "
            "Enabling debug logging and re-scanning will produce a significantly deeper analysis."
        ),
        evidence=[
            f"Plugin 84239 (Authentication Failure Debug Log): not present",
            f"Plugin debugging status: {debugging_status}",
            "Debug logs would reveal: exact SSH commands, per-step auth errors, credential fallback sequence",
        ],
        remediation=[
            "In Tenable, open this scan → More → Configure → Credentials/Settings → enable 'Plugin debugging'",
            f"Launch the scan targeting only this host ({host_data.host_ip}) for faster results",
            "Export the new .nessus file and re-run: host-doctor analyze <new_file> --host " + host_data.host_ip,
            "Alternatively, if API credentials are configured, run with --auto-debug to do this automatically",
        ],
        plugin_ids=[_DEBUG_LOG_PLUGIN_ID],
    )

    return [finding]
