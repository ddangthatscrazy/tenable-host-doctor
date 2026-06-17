"""Authentication analyzer - detect credential issues."""

from typing import Optional

from host_doctor.analyzers.correlation import (
    check_windows_auth_success,
    check_ssh_auth_success,
    check_any_auth_success,
)
from host_doctor.analyzers.helpers import (
    extract_ssh_user_from_output,
    extract_credential_info,
    count_os_specific_plugins,
    count_windows_family_plugins,
    has_bulletin_plugins,
    get_plugin_output_excerpt,
)
from host_doctor.models import Finding, FindingCategory, HostData, ScanConfig, Severity


def analyze_authentication(host_data: HostData, scan_config: ScanConfig) -> list[Finding]:
    """Analyze authentication status and detect credential issues.

    Uses cross-plugin correlation to accurately detect auth success/failure
    by checking multiple plugins, not just primary indicators.

    Checks:
    - Authentication success/failure (with evidence from multiple plugins)
    - SSH password failures (plugin 104410 with specific parsing)
    - SMB invalid credentials (plugin 21745 with specific parsing)
    - Registry access denied (plugin 26917)
    - Credential type mismatches (local vs domain)
    - Partial authentication (connected but limited data)
    - Protocol-specific issues

    Args:
        host_data: Host scan results
        scan_config: Scan configuration

    Returns:
        List of authentication-related findings
    """
    findings = []

    # Use cross-plugin correlation for accurate auth status
    auth_status = check_any_auth_success(host_data)

    # Check for specific SSH password failure (Priority 1)
    ssh_failure = detect_ssh_password_failure(host_data)
    if ssh_failure:
        findings.append(ssh_failure)

    # Check for specific SMB invalid credentials (Priority 1)
    smb_failure = detect_smb_invalid_credentials(host_data)
    if smb_failure:
        findings.append(smb_failure)

    # Check for registry access denied (Priority 1)
    registry_failure = detect_registry_access_denied(host_data, scan_config)
    if registry_failure:
        findings.append(registry_failure)

    # Generic auth failure check (if not already caught by specific checks)
    # BUT: Don't flag as CRITICAL if another auth method succeeded
    if host_data.has_plugin(104410) and not ssh_failure and not smb_failure:
        output = host_data.get_plugin_output(104410)

        # Check if this is SSH failure but Windows auth succeeded
        # (common when SSH creds provided for Windows host)
        is_ssh_failure = output and "Protocol        : SSH" in output
        windows_auth_worked = auth_status["windows"]["success"]

        # If SSH failed but Windows auth worked on a Windows host, downgrade severity
        if is_ssh_failure and windows_auth_worked and host_data.operating_system and "Windows" in host_data.operating_system:
            finding = Finding(
                category=FindingCategory.AUTHENTICATION,
                severity=Severity.INFO,
                title="SSH Credentials Provided for Windows Host",
                description=(
                    "SSH credentials were provided but failed because this is a Windows host. "
                    "However, Windows authentication via SMB succeeded, so the scan is properly credentialed."
                ),
                evidence=[
                    f"Plugin 104410: SSH authentication failed",
                    f"Output: {get_plugin_output_excerpt(output)}",
                    f"OS detected: {host_data.operating_system}",
                    "Windows authentication succeeded (SMB)",
                ],
                remediation=[
                    "Remove SSH credentials from this scan target",
                    "Windows hosts should use SMB/WMI credentials, not SSH",
                    "Current Windows credentials are working correctly",
                ],
                plugin_ids=[104410],
            )
        else:
            # Genuine auth failure
            finding = Finding(
                category=FindingCategory.AUTHENTICATION,
                severity=Severity.CRITICAL,
                title="Authentication Failure",
                description="Credentials were configured but authentication failed for this host.",
                evidence=[
                    f"Plugin 104410 (Credential Authentication Failure) present",
                    f"Output: {get_plugin_output_excerpt(output)}",
                ],
                remediation=[
                    "Verify credentials are correct for this host",
                    "Check if account is locked or expired",
                    "Ensure proper credential type (local vs domain)",
                    "Check firewall allows credential protocols (SSH/WMI/SNMP)",
                ],
                plugin_ids=[104410],
            )
        findings.append(finding)

    # Check Windows authentication with cross-plugin correlation
    windows_auth = auth_status["windows"]
    if windows_auth["success"]:
        # Auth worked - check if we have full data
        if not windows_auth["has_patch_data"]:
            evidence_list = [f"Plugin {pid}: {name}" for pid, name in windows_auth["evidence"]]
            finding = Finding(
                category=FindingCategory.AUTHENTICATION,
                severity=Severity.HIGH,
                title="Windows Partial Authentication - No Patch Data",
                description=(
                    "Windows authentication succeeded but no patch assessment data was collected. "
                    "This indicates the credentials worked but don't have sufficient privileges "
                    "or plugin families are disabled."
                ),
                evidence=[
                    f"Authentication confidence: {windows_auth['confidence']}",
                    "Evidence of auth success:",
                ] + evidence_list + [
                    "No vulnerabilities from Windows patch families",
                    f"OS detected: {host_data.operating_system or 'Unknown'}",
                ],
                remediation=[
                    "Ensure credentials have Administrator privileges",
                    "Set LocalAccountTokenFilterPolicy=1 if using local admin account",
                    "Check if 'Windows' plugin families are enabled in policy",
                    "Verify UAC is not blocking remote administration",
                ],
                plugin_ids=[pid for pid, _ in windows_auth["evidence"] if pid > 0],
            )
            findings.append(finding)

    # Check SSH authentication with cross-plugin correlation
    ssh_auth = auth_status["ssh"]
    if ssh_auth["success"]:
        # Check if this is actually Windows auth misidentified as SSH
        # Plugin 141118 reports all auth types, so check if it's really SSH
        is_actually_windows = (
            windows_auth["success"] and
            host_data.operating_system and
            "Windows" in host_data.operating_system
        )

        if is_actually_windows:
            # This is Windows auth, not SSH - skip the SSH finding
            # (will be handled by Windows auth checks above)
            pass
        elif not ssh_auth["has_patch_data"]:
            # Genuine SSH auth that didn't get patch data
            evidence_list = [f"Plugin {pid}: {name}" for pid, name in ssh_auth["evidence"]]
            finding = Finding(
                category=FindingCategory.AUTHENTICATION,
                severity=Severity.HIGH,
                title="SSH Partial Authentication - No Patch Data",
                description=(
                    "SSH authentication succeeded but no patch assessment data was collected. "
                    "This indicates the credentials worked but don't have sufficient privileges."
                ),
                evidence=[
                    f"Authentication confidence: {ssh_auth['confidence']}",
                    "Evidence of auth success:",
                ] + evidence_list + [
                    "No vulnerabilities from Linux patch families",
                    f"OS detected: {host_data.operating_system or 'Unknown'}",
                ],
                remediation=[
                    "Ensure SSH user has root privileges or sudo access",
                    "Check if Linux patch plugin families are enabled in policy",
                    "Verify sudo is configured if using non-root account",
                ],
                plugin_ids=[pid for pid, _ in ssh_auth["evidence"] if pid > 0],
            )
            findings.append(finding)

    # Check for configured creds but NO auth success
    if (scan_config.has_ssh_creds or scan_config.has_windows_creds) and not auth_status["any_success"]:
        # Only flag if we don't already have an auth failure finding
        if not host_data.has_plugin(104410):
            cred_info = []
            if scan_config.credential_used:
                cred_info.append(f"Credential configured: '{scan_config.credential_used}' via {scan_config.credential_protocol}")
            else:
                cred_info.append(f"SSH credentials configured: {scan_config.has_ssh_creds}")
                cred_info.append(f"Windows credentials configured: {scan_config.has_windows_creds}")

            finding = Finding(
                category=FindingCategory.AUTHENTICATION,
                severity=Severity.HIGH,
                title="Credentials Configured But Not Used",
                description=(
                    "Scan policy has credentials configured, but there's no evidence "
                    "authentication was attempted or succeeded on this host."
                ),
                evidence=cred_info + [
                    f"OS detected: {host_data.operating_system or 'Unknown'}",
                    "No authentication success plugins found",
                    "No authentication failure plugins found",
                ],
                remediation=[
                    "Verify this host's OS matches configured credential types",
                    "Check if authentication-related plugins are enabled",
                    "Ensure host is reachable and services are running",
                    "Check if credential protocol matches host (SSH for Linux, SMB for Windows)",
                ],
                plugin_ids=[],
            )
            findings.append(finding)

    return findings


def detect_ssh_password_failure(host_data: HostData) -> Optional[Finding]:
    """Detect SSH password authentication failures with specific evidence.

    Looks for plugin 104410 with SSH-specific failure messages.
    Provides detailed remediation based on SSH authentication issues.

    Args:
        host_data: Host scan results

    Returns:
        Finding if SSH password failure detected, None otherwise
    """
    if not host_data.has_plugin(104410):
        return None

    output = host_data.get_plugin_output(104410) or ""

    # Check for SSH password failure specifically
    cred_info = extract_credential_info(output)

    if cred_info["protocol"] and "SSH" in cred_info["protocol"].upper():
        if "Failed to authenticate using the supplied password" in output:
            # Extract user if available
            user = cred_info["user"] or extract_ssh_user_from_output(output)

            # Count missing OS-specific plugins
            os_family_count = count_os_specific_plugins(host_data)
            total_plugins = len(host_data.plugins)
            expected_plugins = 90  # Baseline for credentialed Linux

            return Finding(
                category=FindingCategory.AUTHENTICATION,
                severity=Severity.CRITICAL,
                title="SSH Password Authentication Failed",
                description=(
                    f"SSH authentication failed using password for user '{user}'. "
                    f"Missing approximately {expected_plugins - total_plugins} expected plugins due to auth failure."
                ),
                evidence=[
                    "Plugin 104410: SSH password authentication failure",
                    f"User: {user}",
                    f"Protocol: SSH (port {cred_info['port'] or '22'})",
                    f"OS detected: {host_data.operating_system or 'Unknown'}",
                    f"Total plugins: {total_plugins} (expected {expected_plugins}+ for credentialed Linux)",
                    f"OS-specific local checks: {os_family_count} (expected 30+)",
                    "Error: Failed to authenticate using the supplied password",
                ],
                remediation=[
                    f"Verify SSH password for user '{user}' on target host",
                    f"Check if account is locked: passwd -S {user}",
                    "Verify password authentication is enabled in /etc/ssh/sshd_config",
                    "Look for 'PasswordAuthentication yes' in sshd_config",
                    "Try using SSH key authentication instead of passwords",
                    "Check for failed login attempts: tail /var/log/auth.log",
                    f"Test manually: ssh {user}@{host_data.host_ip}",
                ],
                plugin_ids=[104410],
            )

    return None


def detect_smb_invalid_credentials(host_data: HostData) -> Optional[Finding]:
    """Detect SMB invalid credential errors with specific evidence.

    Looks for plugin 21745 with SMB-specific invalid credentials messages.
    Also checks for related registry access issues (plugin 26917).

    Args:
        host_data: Host scan results

    Returns:
        Finding if SMB invalid credentials detected, None otherwise
    """
    if not host_data.has_plugin(21745):
        return None

    output = host_data.get_plugin_output(21745) or ""

    # Check for SMB invalid credentials
    cred_info = extract_credential_info(output)

    if cred_info["protocol"] and "SMB" in cred_info["protocol"].upper():
        if "invalid credentials" in output.lower():
            # Check if registry access is also denied
            has_registry_issue = host_data.has_plugin(26917)

            # Count Windows-specific plugins
            windows_plugin_count = count_windows_family_plugins(host_data)
            total_plugins = len(host_data.plugins)
            expected_plugins = 100  # Baseline for credentialed Windows
            expected_windows = 60

            evidence_list = [
                "Plugin 21745: SMB authentication failure",
                "Error: invalid credentials",
                "Plugin 10394 (SMB Login) failed",
                f"OS detected: {host_data.operating_system or 'Unknown'}",
                f"Total plugins: {total_plugins} (expected {expected_plugins}+ for credentialed Windows)",
                f"Windows plugin count: {windows_plugin_count} (expected {expected_windows}+)",
            ]

            if not has_bulletin_plugins(host_data):
                evidence_list.append("Missing: Windows : Microsoft Bulletins")

            if has_registry_issue:
                evidence_list.append("Also affected: Registry access denied (plugin 26917)")

            user_info = cred_info["user"] or "unknown"
            domain_info = cred_info["domain"] or "unknown"

            return Finding(
                category=FindingCategory.AUTHENTICATION,
                severity=Severity.CRITICAL,
                title="SMB Invalid Credentials",
                description=(
                    f"Windows SMB authentication failed with invalid credentials. "
                    f"Only {windows_plugin_count} Windows plugins executed (expected {expected_windows}+). "
                    f"Missing critical patch assessment capabilities."
                ),
                evidence=evidence_list,
                remediation=[
                    "Verify Windows credentials are correct",
                    f"Check domain vs local account: Current appears to be {domain_info}\\{user_info}",
                    "Ensure account format is correct: DOMAIN\\user or user@domain.com",
                    "Verify account has Administrator privileges (not just Users group)",
                    "Check account is not disabled or expired in AD/local users",
                    f"Test credentials manually: net use \\\\{host_data.host_ip}\\C$ /user:{domain_info}\\{user_info}",
                    "Review Windows Firewall settings for SMB (ports 139, 445)",
                    "Check if SMB signing requirements are blocking connection",
                ],
                plugin_ids=[21745, 10394] + ([26917] if has_registry_issue else []),
            )

    return None


def detect_registry_access_denied(host_data: HostData, scan_config: ScanConfig) -> Optional[Finding]:
    """Detect Windows registry access issues.

    Looks for plugin 26917 which indicates registry access was denied.
    This typically means insufficient privileges or UAC/GPO restrictions.

    Args:
        host_data: Host scan results
        scan_config: Scan configuration

    Returns:
        Finding if registry access denied, None otherwise
    """
    if not host_data.has_plugin(26917):
        return None

    output = host_data.get_plugin_output(26917) or ""

    if "Could not connect to IPC$" in output or "Could not connect to the registry" in output:
        # Check if initial SMB auth worked
        smb_worked = check_windows_auth_success(host_data)["success"]

        evidence_list = [
            "Plugin 26917: Registry access denied",
            f"Error details: {get_plugin_output_excerpt(output, 150)}",
            f"Initial SMB auth: {'Succeeded' if smb_worked else 'Failed'}",
        ]

        if scan_config.credential_used:
            evidence_list.append(f"Credential used: {scan_config.credential_used}")

        evidence_list.extend([
            "Impact: Registry-based checks unavailable",
            "Impact: Patch assessment may be incomplete",
            "Impact: Cannot enumerate installed software fully",
        ])

        return Finding(
            category=FindingCategory.AUTHENTICATION,
            severity=Severity.HIGH,
            title="Windows Registry Access Denied",
            description=(
                "Nessus cannot access the Windows Registry via IPC$. "
                "This indicates insufficient privileges or UAC/GPO restrictions, "
                "even though basic SMB connection may have succeeded."
            ),
            evidence=evidence_list,
            remediation=[
                "Ensure credential has Administrator privileges (not just Users group)",
                "For local admin accounts: Set registry key LocalAccountTokenFilterPolicy=1",
                "Registry path: HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
                "Check UAC settings: Disable UAC or grant Remote UAC privileges",
                "Verify RemoteRegistry service is running and set to Automatic",
                "Check GPO: Computer Config > Administrative Templates > Network > Network Access",
                "Verify 'Network access: Restrict clients allowed to make remote calls to SAM' policy",
                f"Test registry access: reg query \\\\{host_data.host_ip}\\HKLM\\SOFTWARE /s",
            ],
            plugin_ids=[26917],
        )

    return None
