"""Diagnostic tool implementations for the agent.

All tools work on local data (HostData, ScanConfig) - no API calls.
"""

from typing import Any

from host_doctor.models import HostData, ScanConfig


def get_scan_configuration(
    host_data: HostData, scan_config: ScanConfig
) -> dict[str, Any]:
    """Get scan configuration details."""
    return {
        "scan_name": scan_config.scan_name,
        "policy_name": scan_config.policy_name,
        "scanner": scan_config.scanner_name,
        "safe_checks": scan_config.safe_checks_enabled,
        "port_range": scan_config.port_range,
        "max_checks_per_host": scan_config.max_checks_per_host,
        "network_timeout": scan_config.network_timeout,
        "credentials_configured": {
            "windows": scan_config.has_windows_creds,
            "ssh": scan_config.has_ssh_creds,
            "snmp": scan_config.has_snmp_creds,
        },
        "plugin_families_enabled": len(scan_config.enabled_plugin_families),
        "nessus_version": scan_config.nessus_version,
        "plugin_feed": scan_config.plugin_feed_version,
    }


def check_authentication_status(
    host_data: HostData, scan_config: ScanConfig
) -> dict[str, Any]:
    """Check authentication success/failure status using cross-plugin correlation."""
    from host_doctor.analyzers.correlation import check_any_auth_success

    auth = check_any_auth_success(host_data)

    result: dict[str, Any] = {
        "any_success": auth["any_success"],
        "ssh": {
            "success": auth["ssh"]["success"],
            "confidence": auth["ssh"]["confidence"],
            "has_patch_data": auth["ssh"]["has_patch_data"],
            "evidence": [name for _, name in auth["ssh"]["evidence"]],
        },
        "windows": {
            "success": auth["windows"]["success"],
            "confidence": auth["windows"]["confidence"],
            "has_patch_data": auth["windows"]["has_patch_data"],
            "evidence": [name for _, name in auth["windows"]["evidence"]],
        },
        "vmware": {
            "success": auth["vmware"]["success"],
            "confidence": auth["vmware"]["confidence"],
        },
        "auth_failure_plugin": host_data.has_plugin(104410),
        "has_auth_logs": host_data.has_plugin(84239),
        # Partial auth: authenticated but no patch data collected
        "partial_auth": auth["any_success"] and not auth["ssh"]["has_patch_data"] and not auth["windows"]["has_patch_data"],
    }

    # Include failure details if available
    for plugin_id in (104410, 21745):
        if host_data.has_plugin(plugin_id):
            output = host_data.get_plugin_output(plugin_id)
            result["failure_details"] = output[:500] if output else "No details"
            break

    return result


def get_plugin_output(
    host_data: HostData, scan_config: ScanConfig, plugin_id: int
) -> dict[str, Any]:
    """Get raw plugin output text."""
    output = host_data.get_plugin_output(plugin_id)

    if not output:
        return {"plugin_id": plugin_id, "found": False}

    return {"plugin_id": plugin_id, "found": True, "output": output}


def list_failed_plugins(host_data: HostData, scan_config: ScanConfig) -> dict[str, Any]:
    """List plugins that reported errors or failures."""

    ERROR_PLUGIN_IDS = [
        117530,  # Plugin execution errors
        104410,  # Auth failures
        21745,  # Auth failures (older)
    ]

    failed = []
    for plugin_id in ERROR_PLUGIN_IDS:
        if host_data.has_plugin(plugin_id):
            plugin = host_data.plugins.get(plugin_id)
            failed.append(
                {
                    "plugin_id": plugin_id,
                    "plugin_name": plugin.plugin_name if plugin else "Unknown",
                    "output_preview": (
                        plugin.plugin_output[:200] if plugin and plugin.plugin_output else ""
                    ),
                }
            )

    return {"failed_plugins": failed, "count": len(failed)}


def list_vulnerabilities_by_family(
    host_data: HostData, scan_config: ScanConfig, family: str
) -> dict[str, Any]:
    """List vulnerabilities by plugin family."""
    vulns = host_data.get_vulnerabilities_by_family(family)

    return {
        "family": family,
        "count": len(vulns),
        "vulnerabilities": [
            {"plugin_id": v.plugin_id, "name": v.plugin_name, "severity": v.severity}
            for v in vulns[:20]  # Limit to 20 for brevity
        ],
    }


def check_network_connectivity(
    host_data: HostData, scan_config: ScanConfig
) -> dict[str, Any]:
    """Check for network connectivity issues."""

    # Check if host was reachable
    if not host_data.is_reachable:
        return {
            "reachable": False,
            "issue": "Host was not reachable during scan",
            "recommendation": "Check network connectivity, firewall rules, or host availability",
        }

    # Check for timeout patterns
    timeout_indicators = [
        10114,  # ICMP unreachable
        10180,  # Ping host not responsive
    ]

    has_timeouts = any(host_data.has_plugin(p) for p in timeout_indicators)

    return {
        "reachable": host_data.is_reachable,
        "timeouts_detected": has_timeouts,
        "scan_duration_seconds": host_data.scan_duration_seconds,
    }


def check_plugin_coverage(
    host_data: HostData, scan_config: ScanConfig
) -> dict[str, Any]:
    """Check if appropriate plugin families ran for detected OS."""

    os = host_data.operating_system or ""
    expected_families = []

    # Determine expected plugin families based on OS
    if "windows" in os.lower():
        expected_families = [
            "Windows",
            "Windows : Microsoft Bulletins",
            "Windows : User management",
        ]
    elif "linux" in os.lower() or "ubuntu" in os.lower() or "debian" in os.lower():
        expected_families = [
            "Debian Local Security Checks",
            "Ubuntu Local Security Checks",
            "Red Hat Local Security Checks",
        ]
    elif "red hat" in os.lower() or "centos" in os.lower():
        expected_families = ["Red Hat Local Security Checks", "CentOS Local Security Checks"]

    # Check which families actually ran
    families_found = []
    families_missing = []

    for family in expected_families:
        vulns = host_data.get_vulnerabilities_by_family(family)
        if vulns:
            families_found.append(family)
        else:
            families_missing.append(family)

    return {
        "detected_os": os,
        "expected_families": expected_families,
        "families_found": families_found,
        "families_missing": families_missing,
        "coverage_issue": len(families_missing) > 0,
    }


def check_scan_timing(host_data: HostData, scan_config: ScanConfig) -> dict[str, Any]:
    """Analyze scan timing and duration."""

    duration = host_data.scan_duration_seconds

    if not duration:
        return {"timing_data_available": False}

    # Flag anomalies
    issues = []

    if duration < 10:
        issues.append("Scan completed suspiciously fast (< 10s) - likely errors")

    if duration > 3600:
        issues.append("Scan took over 1 hour - potential timeout or performance issues")

    return {
        "timing_data_available": True,
        "duration_seconds": duration,
        "duration_human": f"{int(duration // 60)}m {int(duration % 60)}s",
        "timing_issues": issues,
    }


def compare_with_expected_results(
    host_data: HostData, scan_config: ScanConfig
) -> dict[str, Any]:
    """Compare what should have happened vs what actually happened."""

    discrepancies = []

    # Check: credentials configured but no auth success
    if (scan_config.has_windows_creds or scan_config.has_ssh_creds) and not (
        host_data.has_plugin(141118) or host_data.has_plugin(102094)
    ):
        discrepancies.append(
            "Credentials configured but authentication did not succeed"
        )

    # Check: auth success but no local checks
    if host_data.has_plugin(141118) or host_data.has_plugin(102094):
        patch_families = ["Windows : Microsoft Bulletins", "Red Hat Local Security Checks"]
        has_patches = any(
            len(host_data.get_vulnerabilities_by_family(f)) > 0 for f in patch_families
        )

        if not has_patches:
            discrepancies.append(
                "Authentication succeeded but no patch data collected - plugin families may be disabled"
            )

    # Check: safe checks enabled on test environment
    if scan_config.safe_checks_enabled:
        scan_name = scan_config.scan_name or ""
        if any(
            keyword in scan_name.lower() for keyword in ["test", "dev", "lab", "staging"]
        ):
            discrepancies.append(
                "Safe checks enabled on test/dev environment - may miss vulnerabilities"
            )

    return {"discrepancies": discrepancies, "count": len(discrepancies)}


def analyze_credential_configuration(
    host_data: HostData, scan_config: ScanConfig
) -> dict[str, Any]:
    """Analyze credential configuration for mismatches."""

    issues = []

    # This would need plugin 19506 output to see actual credential config details
    # For now, we can check for common patterns in plugin outputs

    # Check for NT_STATUS_LOGON_FAILURE (wrong creds or local vs domain mismatch)
    auth_failure_output = host_data.get_plugin_output(104410)
    if auth_failure_output and "NT_STATUS_LOGON_FAILURE" in auth_failure_output:
        issues.append(
            "SMB authentication failure - possible wrong credentials or local vs domain account mismatch"
        )

    # Check for SSH key vs password issues
    if host_data.has_plugin(141118):
        ssh_output = host_data.get_plugin_output(141118)
        if ssh_output and "password" in ssh_output.lower():
            issues.append(
                "SSH password authentication used - consider SSH keys for better reliability"
            )

    return {"credential_issues": issues, "count": len(issues)}


def check_for_timeout_patterns(
    host_data: HostData, scan_config: ScanConfig
) -> dict[str, Any]:
    """Look for patterns indicating timeout issues."""

    timeout_indicators = []

    # Check scan duration vs configured timeout
    if (
        scan_config.network_timeout
        and host_data.scan_duration_seconds
        and host_data.scan_duration_seconds > (scan_config.network_timeout * 10)
    ):
        timeout_indicators.append(
            f"Scan duration ({host_data.scan_duration_seconds}s) much longer than network timeout ({scan_config.network_timeout}s)"
        )

    # Check for incomplete results (scan stopped early)
    if not host_data.scan_completed:
        timeout_indicators.append("Scan did not complete normally")

    # Check for timeout-related plugins
    if host_data.has_plugin(10114):  # ICMP unreachable
        timeout_indicators.append("ICMP unreachable messages detected")

    return {"timeout_patterns": timeout_indicators, "count": len(timeout_indicators)}


def detect_firewall_blocking(
    host_data: HostData, scan_config: ScanConfig
) -> dict[str, Any]:
    """Detect patterns suggesting firewall blocking."""

    blocking_indicators = []

    # Very few open ports found
    open_ports = [v.port for v in host_data.vulnerabilities if v.port]
    unique_ports = len(set(open_ports))

    if unique_ports < 3:
        blocking_indicators.append(
            f"Only {unique_ports} unique ports found - possible firewall filtering"
        )

    # Check for service detection failures
    # This would be indicated by lack of service info plugins

    # Check for port scan vs service scan discrepancy
    # (ports open but no service info)

    return {
        "blocking_indicators": blocking_indicators,
        "open_ports_count": unique_ports,
        "count": len(blocking_indicators),
    }
