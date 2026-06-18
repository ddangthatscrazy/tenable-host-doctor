"""Scanner-route analyzer — distinguish a scanner-vantage problem from a target
problem, using ONLY signals strong enough to stand on a single host's evidence.

Deliberately NOT implemented here:
- "Scanner may be in wrong network zone": the original proposal inferred this from
  an RFC1918 target + a cloud/unknown scanner, or from the scanner's *name*. That is
  speculation, not evidence (a cloud scanner in a peered VPC is correctly placed), so
  a HIGH finding there would be noise. Omitted on purpose.
- A standalone "middlebox interfering" finding: plugin 27576 (firewall detection) is
  already used as context elsewhere and is suggestive, not proof, so here it is folded
  in as corroborating EVIDENCE on the latency finding rather than asserted on its own.

The genuinely strong version of scanner-route diagnosis is SCAN-LEVEL: if most hosts
behind one scanner show the same problem, that's far stronger than one host. That
belongs in a separate scan-level correlation layer, not in this per-host tool.
"""

from host_doctor.models import Finding, FindingCategory, HostData, ScanConfig, Severity

P_FIREWALL_DETECTED = 27576

LATENCY_HIGH_MS = 100          # scanner-to-target RTT above this is notably elevated
SLOW_SCAN_SECONDS = 600        # corroborating "this scan was slow"
ELEVATED_TIMEOUT_SECONDS = 10  # someone may have raised the timeout to cope with latency

# "Clearly high" concurrency settings (defaults are ~5 checks/host, ~30 hosts/scan).
MAX_CHECKS_HIGH = 10
MAX_HOSTS_HIGH = 100
MAX_TCP_PER_HOST_HIGH = 20


def analyze_scanner_route(host_data: HostData, scan_config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []

    # Scanner-vantage concepts; agents run on the host itself.
    if getattr(scan_config, "sensor_type", None) == "agent":
        return findings

    duration = host_data.scan_duration_seconds
    slow = duration is not None and duration > SLOW_SCAN_SECONDS
    timeout = scan_config.network_timeout
    elevated_timeout = timeout is not None and timeout > ELEVATED_TIMEOUT_SECONDS

    # 1. High scanner-to-target latency — only with a corroborating symptom, so we
    #    don't flag benign high RTT that caused no problem.
    rtt = scan_config.ping_rtt_ms
    if rtt is not None and rtt > LATENCY_HIGH_MS and (slow or elevated_timeout):
        evidence = [f"Ping RTT scanner→target: {rtt:.0f} ms (elevated)."]
        if slow:
            evidence.append(f"Scan was slow ({duration:.0f}s), consistent with latency dragging checks.")
        if elevated_timeout:
            evidence.append(f"Network timeout raised to {timeout}s, often a response to latency.")
        if host_data.has_plugin(P_FIREWALL_DETECTED):
            evidence.append(
                "Firewall/middlebox context: plugin 27576 detected on the path — a middlebox "
                "may be adding latency or filtering (suggestive, not conclusive)."
            )
        findings.append(Finding(
            category=FindingCategory.NETWORK,
            severity=Severity.MEDIUM,
            title="High Scanner-to-Target Latency",
            description=(
                "Round-trip time from the scanner to this host is high and the scan shows symptoms "
                "consistent with it (slowness / raised timeout). A distant scanner or a constrained "
                "path can reduce reliability of timing-sensitive checks. Consider whether a scanner "
                "closer to this target's network would assess it more reliably."
            ),
            evidence=evidence,
            remediation=[
                "Consider scanning this target from a scanner with better network proximity.",
                "Review the scanner-to-target path for congestion or rate-limiting middleboxes.",
            ],
            plugin_ids=[P_FIREWALL_DETECTED] if host_data.has_plugin(P_FIREWALL_DETECTED) else [],
            confidence=0.6,
        ))

    # 2. Scanner load may be reducing fidelity — high concurrency settings on a slow
    #    scan. Distinct from the tuning analyzer (which looks at thorough/UDP/timeout):
    #    this looks specifically at concurrency/load, framed around result fidelity.
    high_load = []
    if (scan_config.max_checks_per_host or 0) >= MAX_CHECKS_HIGH:
        high_load.append(f"max checks/host = {scan_config.max_checks_per_host}")
    if (scan_config.max_hosts_per_scan or 0) >= MAX_HOSTS_HIGH:
        high_load.append(f"max hosts/scan = {scan_config.max_hosts_per_scan}")
    if (scan_config.max_tcp_sessions_per_host or 0) >= MAX_TCP_PER_HOST_HIGH:
        high_load.append(f"max TCP sessions/host = {scan_config.max_tcp_sessions_per_host}")

    if slow and high_load:
        findings.append(Finding(
            category=FindingCategory.PERFORMANCE,
            severity=Severity.MEDIUM,
            title="Scanner Load May Be Affecting Result Fidelity",
            description=(
                "This scan was slow and runs with high concurrency settings (" + "; ".join(high_load) +
                "). A scanner pushed to high concurrency can drop or rush timing-sensitive checks, "
                "reducing result fidelity — not just speed. This is a lead to check, not a confirmed cause."
            ),
            evidence=[f"Scan duration: {duration:.0f}s."] + [f"Elevated: {h}." for h in high_load],
            remediation=[
                "Lower concurrency (max checks per host / max hosts per scan / TCP sessions) and re-test.",
                "Confirm the scanner has adequate CPU/memory for its assigned load.",
            ],
            plugin_ids=[],
            confidence=0.5,
        ))

    return findings
