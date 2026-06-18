"""Network analyzer - detect connectivity and timeout issues."""

from host_doctor.models import Finding, FindingCategory, HostData, ScanConfig, Severity

# Local port enumerators. When any of these ran, Nessus enumerated ports locally
# (netstat/SNMP), the effective range becomes "all", and network port scanners are
# disabled — so a low open-port count reflects the host's actual listening services,
# not firewall filtering. (Verified against Tenable's Useful Plugins Guide.)
LOCAL_PORT_ENUM_PLUGINS = {
    14272: "Netstat Portscanner (SSH)",
    34220: "Netstat Portscanner (WMI)",
    14274: "Nessus SNMP Scanner",
}


def _is_narrow_port_range(port_range: str) -> bool:
    """True if the configured range is an explicit short list (few ports by design).

    "default" (~4,790 ports) and "all" (65,536) are broad. A span like "1-1024" is
    broad enough that few open ports is still meaningful, so spans are not narrow.
    An explicit comma list of <=20 individual ports IS narrow.
    """
    pr = port_range.strip().lower()
    if not pr or pr in ("default", "all") or "-" in pr:
        return False
    parts = [p for p in pr.replace(" ", "").split(",") if p]
    return 0 < len(parts) <= 20


def _low_port_count_explained(host_data: HostData, scan_config: ScanConfig):
    """Return a reason string if a low open-port count is expected, else None.

    This prevents "Limited Port Access" from blaming a firewall when the scan
    config or method already explains the result. Note: SYN being the scanner is
    NOT a reason — SYN is a full network port scanner that covers the whole range.
    """
    # 1. Local port enumeration ran -> count reflects actual listening services.
    for pid, name in LOCAL_PORT_ENUM_PLUGINS.items():
        if host_data.has_plugin(pid):
            return (
                f"Local port enumeration ran ({name}, plugin {pid}); the open-port list "
                "reflects the host's actual listening services, not firewall filtering."
            )
    # 2. Narrow configured port range -> few open ports is expected by design.
    pr = getattr(scan_config, "port_range", None)
    if pr and _is_narrow_port_range(pr):
        return f"The scan's configured port range ('{pr}') is narrow, so a low open-port count is expected."
    return None


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

    # Agent scans perform no network reachability or port scanning, so none of the
    # connectivity findings below apply. Return early to prevent false positives —
    # most importantly a CRITICAL "Host Unreachable" that would contradict the
    # AGENT_NO_DATA verdict, and "Suspiciously Fast Scan" (agents are legitimately fast).
    if getattr(scan_config, "sensor_type", None) == "agent":
        return findings

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

    # NOTE: plugins 10114 ("ICMP Timestamp Request Remote Date Disclosure") and
    # 10180 ("Ping the remote host") are RESPONSE indicators — their presence means
    # the host answered discovery, not that it timed out. Non-response is signaled by
    # their ABSENCE, which is already covered by the is_reachable check above. We do
    # not emit a timeout finding from their presence (that was the previous bug).

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

    # Check for very few open ports (possible firewall blocking).
    # Skip for agent scans (no network port scanning) and when the scan config or
    # method already explains the low count (narrow range or local enumeration).
    open_ports = set()
    for vuln in host_data.vulnerabilities:
        if vuln.port:
            open_ports.add(vuln.port)

    port_count_explanation = _low_port_count_explained(host_data, scan_config)

    if (
        getattr(scan_config, "sensor_type", None) != "agent"
        and port_count_explanation is None
        and len(open_ports) < 3
        and len(host_data.vulnerabilities) > 0
    ):
        port_evidence = [
            f"Open ports found: {sorted(list(open_ports))}",
            "Typical servers have 5-20+ accessible ports",
            "May indicate host-based firewall or network filtering",
        ]
        # 27576 (Firewall Detection) is supporting context, not proof: it means the
        # host *appears* protected by a firewall based on SYN/TCP scanner responses.
        if host_data.has_plugin(27576):
            port_evidence.append(
                "Firewall/filtering context: plugin 27576 detected — the host appears to be "
                "behind a firewall (based on SYN/TCP scanner responses), consistent with filtering."
            )
        finding = Finding(
            category=FindingCategory.NETWORK,
            severity=Severity.MEDIUM,
            title="Limited Port Access",
            description=(
                f"Only {len(open_ports)} unique ports found open. This may indicate "
                "firewall filtering or restrictive network ACLs."
            ),
            evidence=port_evidence,
            remediation=[
                "Review firewall rules on target host",
                "Check network ACLs/security groups",
                "Verify scanner can reach all required ports",
                "Consider using different port scan range",
            ],
            plugin_ids=[27576] if host_data.has_plugin(27576) else [],
        )
        findings.append(finding)

    return findings
