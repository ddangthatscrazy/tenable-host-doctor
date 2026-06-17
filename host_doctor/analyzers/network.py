"""Network analyzer - detect connectivity and timeout issues."""

from host_doctor.models import Finding, FindingCategory, HostData, ScanConfig, Severity


def analyze_network(host_data: HostData, scan_config: ScanConfig) -> list[Finding]:
    """Analyze network connectivity and timeout issues.

    Checks:
    - Host reachability
    - Timeout patterns
    - Scan duration anomalies
    - Firewall blocking indicators

    Args:
        host_data: Host scan results
        scan_config: Scan configuration

    Returns:
        List of network-related findings
    """
    findings = []

    # Check if host was unreachable
    if not host_data.is_reachable:
        finding = Finding(
            category=FindingCategory.NETWORK,
            severity=Severity.CRITICAL,
            title="Host Unreachable",
            description="The target host did not respond during the scan.",
            evidence=[
                f"Host IP: {host_data.host_ip}",
                "No vulnerabilities or responses detected",
                "Host may be offline, firewalled, or network path is blocked",
            ],
            remediation=[
                "Verify host is online and responding to ping",
                "Check firewall rules between scanner and target",
                "Ensure scanner is in correct network zone",
                "Check if host IP is correct",
            ],
            plugin_ids=[],
        )
        findings.append(finding)
        return findings  # No point checking other network issues if unreachable

    # Check for timeout patterns
    if host_data.has_plugin(10114) or host_data.has_plugin(10180):
        finding = Finding(
            category=FindingCategory.NETWORK,
            severity=Severity.MEDIUM,
            title="Network Timeout Detected",
            description="Network timeout or ICMP unreachable messages detected during scan.",
            evidence=[
                "Plugin 10114 or 10180 present",
                "May indicate network latency or packet loss",
            ],
            remediation=[
                "Check network path between scanner and target",
                "Consider increasing network timeout in scan settings",
                "Verify no rate limiting or QoS restrictions",
            ],
            plugin_ids=[10114, 10180],
        )
        findings.append(finding)

    # Check for scan duration anomalies
    if host_data.scan_duration_seconds:
        duration = host_data.scan_duration_seconds

        if duration < 10:
            finding = Finding(
                category=FindingCategory.PERFORMANCE,
                severity=Severity.HIGH,
                title="Suspiciously Fast Scan",
                description=(
                    f"Scan completed in only {int(duration)} seconds, which is unusually fast. "
                    "This may indicate the scan encountered errors and exited early."
                ),
                evidence=[
                    f"Scan duration: {int(duration)}s",
                    f"Vulnerabilities found: {len(host_data.vulnerabilities)}",
                    "Typical scans take at least 30-60 seconds",
                ],
                remediation=[
                    "Review scan logs for errors",
                    "Check if scan was manually stopped",
                    "Verify scanner had network connectivity throughout scan",
                ],
                plugin_ids=[],
            )
            findings.append(finding)

        elif duration > 3600:
            finding = Finding(
                category=FindingCategory.PERFORMANCE,
                severity=Severity.MEDIUM,
                title="Unusually Long Scan Duration",
                description=(
                    f"Scan took {int(duration / 60)} minutes, which is longer than typical. "
                    "This may indicate network issues, host performance problems, or timeout issues."
                ),
                evidence=[
                    f"Scan duration: {int(duration / 60)} minutes",
                    f"Network timeout configured: {scan_config.network_timeout}s" if scan_config.network_timeout else "Network timeout: not specified",
                ],
                remediation=[
                    "Check network latency between scanner and target",
                    "Consider increasing max checks per host if host is slow",
                    "Verify target host has adequate resources",
                    "Check for network bandwidth constraints",
                ],
                plugin_ids=[],
            )
            findings.append(finding)

    # Check for very few open ports (possible firewall blocking)
    open_ports = set()
    for vuln in host_data.vulnerabilities:
        if vuln.port:
            open_ports.add(vuln.port)

    if len(open_ports) < 3 and len(host_data.vulnerabilities) > 0:
        finding = Finding(
            category=FindingCategory.NETWORK,
            severity=Severity.MEDIUM,
            title="Limited Port Access",
            description=(
                f"Only {len(open_ports)} unique ports found open. This may indicate "
                "firewall filtering or restrictive network ACLs."
            ),
            evidence=[
                f"Open ports found: {sorted(list(open_ports))}",
                "Typical servers have 5-20+ accessible ports",
                "May indicate host-based firewall or network filtering",
            ],
            remediation=[
                "Review firewall rules on target host",
                "Check network ACLs/security groups",
                "Verify scanner can reach all required ports",
                "Consider using different port scan range",
            ],
            plugin_ids=[],
        )
        findings.append(finding)

    return findings
