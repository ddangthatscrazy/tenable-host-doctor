"""Plugin coverage analyzer - detect insufficient plugin coverage and missing families."""

from typing import Optional

from host_doctor.analyzers.helpers import (
    count_os_specific_plugins,
    count_windows_family_plugins,
    extract_open_ports,
    get_plugin_families_present,
    has_ssh_indicators,
    has_smb_indicators,
)
from host_doctor.models import Finding, FindingCategory, HostData, ScanConfig, Severity


class PluginCoverageBaseline:
    """Expected plugin counts by OS and authentication status."""

    LINUX_CREDENTIALED = {
        "total_min": 80,
        "total_max": 120,
        "os_family_min": 30,  # e.g., "CentOS Local Security Checks"
        "critical_families": [
            "CentOS Local Security Checks",
            "Red Hat Local Security Checks",
            "Ubuntu Local Security Checks",
            "Oracle Linux Local Security Checks",
            "Amazon Linux Local Security Checks",
            "Debian Local Security Checks",
            "SuSE Local Security Checks",
            "Fedora Local Security Checks",
        ],
    }

    WINDOWS_CREDENTIALED = {
        "total_min": 80,
        "total_max": 150,
        "windows_family_min": 50,  # "Windows" family
        "critical_families": [
            "Windows",
            "Windows : Microsoft Bulletins",
            "Windows : User management",
        ],
    }

    NON_CREDENTIALED = {
        "total_min": 20,
        "total_max": 60,
        "general_family": 15,
    }


def analyze_plugin_coverage(host_data: HostData, scan_config: ScanConfig) -> list[Finding]:
    """Compare actual plugin coverage against baseline expectations.

    Coverage findings are gated on the authoritative "did local checks run?"
    signal from the credential-state classifier. Raw plugin counts are brittle
    (a minimal RHEL box and a Windows box running SQL+IIS have wildly different
    legitimate counts), so when the classifier confirms credentialed assessment
    succeeded we do NOT raise count-based coverage findings — they would be false
    positives. Counts only matter when local checks did not run.

    Args:
        host_data: Host scan results
        scan_config: Scan configuration

    Returns:
        List of coverage-related findings
    """
    from host_doctor.analyzers.credential_state import (
        RootCause,
        classify_credential_state,
    )

    findings = []

    # Authoritative gate: if credentialed local checks actually ran, the host is
    # covered regardless of absolute plugin count. Skip the count baselines.
    state = classify_credential_state(host_data)
    if state.root_cause == RootCause.SUCCESS:
        return findings

    # Use vulnerabilities (all report items) not plugins dict (filtered subset)
    actual_count = len(host_data.vulnerabilities)
    os_name = host_data.operating_system or ""
    os_lower = os_name.lower()

    # Determine if scan should be credentialed based on config
    is_credentialed = (
        scan_config.credential_used is not None
        or scan_config.has_ssh_creds
        or scan_config.has_windows_creds
    )

    # Check Linux coverage
    if any(keyword in os_lower for keyword in ["linux", "centos", "ubuntu", "redhat", "oracle", "debian", "fedora"]):
        finding = check_linux_coverage(host_data, actual_count, is_credentialed)
        if finding:
            findings.append(finding)

    # Check Windows coverage
    elif "windows" in os_lower:
        finding = check_windows_coverage(host_data, actual_count, is_credentialed)
        if finding:
            findings.append(finding)

    # Check for minimal coverage regardless of OS
    minimal_finding = detect_minimal_coverage(host_data, scan_config)
    if minimal_finding:
        findings.append(minimal_finding)

    return findings


def check_linux_coverage(
    host_data: HostData, actual_count: int, is_credentialed: bool
) -> Optional[Finding]:
    """Check if Linux host has sufficient plugin coverage.

    Args:
        host_data: Host scan results
        actual_count: Total plugin count
        is_credentialed: Whether credentials were configured

    Returns:
        Finding if coverage is insufficient, None otherwise
    """
    if not is_credentialed:
        # Non-credentialed is expected to be lower
        return None

    baseline = PluginCoverageBaseline.LINUX_CREDENTIALED
    expected_min = baseline["total_min"]
    expected_max = baseline["total_max"]
    expected_os_family = baseline["os_family_min"]

    if actual_count < expected_min:
        # Severe coverage gap
        os_family_count = count_os_specific_plugins(host_data)
        coverage_pct = int((actual_count / expected_min) * 100)

        return Finding(
            category=FindingCategory.CONFIGURATION,
            severity=Severity.HIGH,  # corroborating; auth analyzer owns CRITICAL
            title="Low Plugin Coverage for Linux Host",
            description=(
                f"Host has only {actual_count} plugins (expected {expected_min}-{expected_max} "
                f"for credentialed Linux). OS-specific checks: {os_family_count} (expected {expected_os_family}+). "
                f"Coverage: {coverage_pct}%."
            ),
            evidence=[
                f"Actual plugins: {actual_count}",
                f"Expected for credentialed Linux: {expected_min}-{expected_max}",
                f"OS family plugins: {os_family_count} (expected {expected_os_family}+)",
                f"Coverage: {coverage_pct}%",
                f"Grade: {'F' if coverage_pct < 30 else 'D'}",
                f"OS detected: {host_data.operating_system or 'Unknown'}",
            ],
            remediation=[
                "See the Authentication finding for the confirmed root cause (this is a corroborating coverage signal).",
                "Check SSH credentials and connectivity (look for plugin 97993 success)",
                "Verify all plugin families are enabled in scan policy",
                "Ensure user has sufficient privileges (root or sudo)",
                "Check for plugin 104410 or 21745 indicating auth failure",
            ],
            plugin_ids=[],
        )

    return None


def check_windows_coverage(
    host_data: HostData, actual_count: int, is_credentialed: bool
) -> Optional[Finding]:
    """Check if Windows host has sufficient plugin coverage.

    Args:
        host_data: Host scan results
        actual_count: Total plugin count
        is_credentialed: Whether credentials were configured

    Returns:
        Finding if coverage is insufficient, None otherwise
    """
    if not is_credentialed:
        # Non-credentialed is expected to be lower
        return None

    baseline = PluginCoverageBaseline.WINDOWS_CREDENTIALED
    expected_min = baseline["total_min"]
    expected_max = baseline["total_max"]
    windows_family_min = baseline["windows_family_min"]

    if actual_count < expected_min:
        windows_plugin_count = count_windows_family_plugins(host_data)
        coverage_pct = int((actual_count / expected_min) * 100)

        return Finding(
            category=FindingCategory.CONFIGURATION,
            severity=Severity.HIGH,  # corroborating; auth analyzer owns CRITICAL
            title="Low Plugin Coverage for Windows Host",
            description=(
                f"Host has only {actual_count} plugins (expected {expected_min}-{expected_max} "
                f"for credentialed Windows). Windows family: {windows_plugin_count} (expected {windows_family_min}+). "
                f"Coverage: {coverage_pct}%."
            ),
            evidence=[
                f"Actual plugins: {actual_count}",
                f"Expected for credentialed Windows: {expected_min}-{expected_max}",
                f"Windows family plugins: {windows_plugin_count} (expected {windows_family_min}+)",
                f"Coverage: {coverage_pct}%",
                f"Grade: {'F' if coverage_pct < 30 else 'D'}",
                f"OS detected: {host_data.operating_system or 'Unknown'}",
            ],
            remediation=[
                "See the Authentication finding for the confirmed root cause (this is a corroborating coverage signal).",
                "Check SMB credentials and connectivity (look for plugin 10394 success)",
                "Verify Windows plugin families are enabled in scan policy",
                "Ensure account has Administrator privileges",
                "Check for plugin 104410 or 21745 indicating auth failure",
                "Verify LocalAccountTokenFilterPolicy=1 if using local admin",
            ],
            plugin_ids=[],
        )

    return None


def detect_minimal_coverage(host_data: HostData, scan_config: ScanConfig) -> Optional[Finding]:
    """Detect hosts with minimal plugin coverage indicating severe issues.

    Less than 10 plugins typically indicates:
    - Severe firewall restrictions
    - Network unreachability issues
    - Scan policy problems
    - Complete authentication failure

    Args:
        host_data: Host scan results
        scan_config: Scan configuration

    Returns:
        Finding if minimal coverage detected, None otherwise
    """
    plugin_count = len(host_data.vulnerabilities)

    if plugin_count < 10:
        # Severe coverage issue
        open_ports = extract_open_ports(host_data)

        # Check if marked as credentialed
        is_credentialed = (
            scan_config.credential_used is not None
            or scan_config.has_ssh_creds
            or scan_config.has_windows_creds
        )

        evidence_list = [
            f"Total plugins: {plugin_count} (expected 50+ for typical host)",
            f"Open ports found: {len(open_ports)}",
        ]

        if open_ports:
            port_list = ", ".join(map(str, open_ports[:10]))
            evidence_list.append(f"Ports: {port_list}")
        else:
            evidence_list.append("No open ports detected!")

        evidence_list.extend([
            f"Marked as credentialed: {is_credentialed}",
            f"OS detected: {host_data.operating_system or 'None'}",
            "Note: Most servers have 5-20+ accessible ports",
        ])

        return Finding(
            category=FindingCategory.NETWORK,
            severity=Severity.CRITICAL if is_credentialed else Severity.HIGH,
            title="Minimal Plugin Coverage - Severe Restrictions",
            description=(
                f"Only {plugin_count} plugins executed. This indicates severe firewall "
                f"restrictions, network issues, or scan policy problems. Expected at least 50 plugins."
            ),
            evidence=evidence_list,
            remediation=[
                "Check firewall rules on target host (iptables/Windows Firewall)",
                "Verify network ACLs/security groups allow scanner access",
                "Confirm host is reachable: ping test, traceroute",
                "Review scan policy - ensure plugin families are enabled",
                "Check scan logs for timeout issues",
                "Verify scanner can reach required ports:",
                "  - SSH: port 22",
                "  - SMB: ports 139, 445",
                "  - WMI: port 135",
                "  - HTTP/HTTPS: ports 80, 443",
                f"Test connectivity: nmap -p- {host_data.host_ip}",
            ],
            plugin_ids=[],
        )

    return None


def detect_missing_critical_families(host_data: HostData) -> list[Finding]:
    """Detect when critical plugin families are missing.

    Checks for OS-specific families that should be present for
    credentialed scans.

    Args:
        host_data: Host scan results

    Returns:
        List of findings for missing families
    """
    findings = []
    os_name = (host_data.operating_system or "").lower()

    # Get all plugin families present
    families_present = get_plugin_families_present(host_data)

    # Check for Linux critical families
    if any(os_keyword in os_name for os_keyword in ["linux", "centos", "ubuntu", "redhat", "oracle", "debian"]):
        if has_ssh_indicators(host_data):
            critical_linux_families = PluginCoverageBaseline.LINUX_CREDENTIALED["critical_families"]

            # Check if ANY OS-specific family is present
            has_os_family = any(family in families_present for family in critical_linux_families)

            if not has_os_family:
                finding = Finding(
                    category=FindingCategory.POLICY,
                    severity=Severity.HIGH,
                    title="Missing Critical Plugin Families: Linux Local Checks",
                    description=(
                        f"OS detected as Linux but no OS-specific local security check families found. "
                        f"This typically indicates authentication failed or plugin families are disabled."
                    ),
                    evidence=[
                        f"OS detected: {host_data.operating_system}",
                        f"Expected one of: {', '.join(critical_linux_families[:3])}...",
                        f"Families present: {len(families_present)}",
                        f"Has SSH indicators: Yes",
                    ],
                    remediation=[
                        "Verify SSH authentication succeeded (check plugin 97993)",
                        "Enable all plugin families in scan policy",
                        "Check if Safe Checks is preventing local checks",
                        "Ensure credentials have sufficient privileges (root or sudo)",
                    ],
                    plugin_ids=[],
                )
                findings.append(finding)

    # Check for Windows critical families
    elif "windows" in os_name:
        if has_smb_indicators(host_data):
            if "Windows" not in families_present:
                finding = Finding(
                    category=FindingCategory.POLICY,
                    severity=Severity.HIGH,
                    title="Missing Critical Plugin Family: Windows",
                    description=(
                        "OS detected as Windows but 'Windows' plugin family has no results. "
                        "This indicates authentication failed or family is disabled."
                    ),
                    evidence=[
                        f"OS detected: {host_data.operating_system}",
                        "Missing family: Windows (0 plugins)",
                        f"Families present: {len(families_present)}",
                        f"Has SMB indicators: Yes",
                    ],
                    remediation=[
                        "Verify SMB authentication succeeded (check plugin 10394)",
                        "Enable Windows plugin family in scan policy",
                        "Check credential privileges (needs Administrator)",
                        "Verify LocalAccountTokenFilterPolicy=1 for local admin accounts",
                    ],
                    plugin_ids=[],
                )
                findings.append(finding)

            elif "Windows : Microsoft Bulletins" not in families_present:
                # Windows family present but no bulletins
                finding = Finding(
                    category=FindingCategory.POLICY,
                    severity=Severity.MEDIUM,
                    title="Missing Plugin Family: Windows Bulletins",
                    description=(
                        "Windows family present but no Microsoft Bulletins plugins executed. "
                        "Patch assessment may be incomplete."
                    ),
                    evidence=[
                        "Windows family: Present",
                        "Windows : Microsoft Bulletins: Missing",
                        "Impact: Cannot detect missing Windows patches",
                    ],
                    remediation=[
                        "Enable 'Windows : Microsoft Bulletins' family in scan policy",
                        "Verify policy is configured for patch detection",
                        "Check if registry access is working (plugin 26917)",
                    ],
                    plugin_ids=[],
                )
                findings.append(finding)

    return findings
