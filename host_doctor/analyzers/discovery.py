"""Discovery analyzer — explain why a NETWORK scan failed to establish host liveness.

Runs only for network scans where no data came back (is_reachable False, i.e. the
scanner never got results for this host). It turns a bare "Host Unreachable" into
actionable discovery diagnosis, while refusing to assert what it can't prove: from
ONE host's export you cannot distinguish "discovery misconfigured" from "host
genuinely powered off", so the restrictive-discovery finding is a possibility, not
a verdict. Several triggers depend on policy-preference fields that are parsed
best-effort; when those are absent the corresponding finding simply does not fire.
"""

from host_doctor.models import Finding, FindingCategory, HostData, ScanConfig, Severity

P_PING_RESPONSE = 10180   # Ping the remote host (response indicator)
P_SCAN_INFO = 19506       # Nessus Scan Information
P_LAUNCHED = 112154       # Enumerate Launched Plugins


def analyze_discovery(host_data: HostData, scan_config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []

    # Discovery is a network-scan concept; agents run locally and don't do it.
    if getattr(scan_config, "sensor_type", None) == "agent":
        return findings
    # Only relevant when nothing came back — that's what "discovery failed" means here.
    if host_data.is_reachable:
        return findings

    # 1. Deterministic: the policy is configured to skip unresponsive hosts, so a
    #    discovery miss means the host was never assessed. Factual, not inferred.
    if scan_config.scan_unresponsive_hosts is False:
        findings.append(Finding(
            category=FindingCategory.NETWORK,
            severity=Severity.MEDIUM,
            title="Scanner Did Not Continue Assessment After Discovery Failure",
            description=(
                "The host was not established as alive during discovery, and the scan policy is "
                "configured NOT to scan unresponsive hosts — so no assessment was attempted. This "
                "is a deterministic consequence of the config, not a credential problem."
            ),
            evidence=[
                "No assessment data returned for this host.",
                "Policy: scan unresponsive hosts = disabled.",
            ],
            remediation=[
                "For a diagnostic run, enable 'Scan unresponsive hosts' to force assessment.",
                "Or fix discovery so the host is detected as alive (see discovery guidance below).",
            ],
            plugin_ids=[],
            confidence=1.0,
        ))

    # 2. Possibility (NOT a verdict): narrow discovery may miss a host that filters
    #    ICMP. Only fires when we actually parsed narrow discovery methods.
    methods = scan_config.host_discovery_methods or []
    if methods and "TCP" not in methods and not host_data.has_plugin(P_PING_RESPONSE):
        findings.append(Finding(
            category=FindingCategory.NETWORK,
            severity=Severity.MEDIUM,
            title="Host Discovery May Be Too Restrictive",
            description=(
                f"Discovery used {', '.join(methods)} only and the host was not detected. IF the host "
                "is actually up, this may be too narrow to find it — a host that filters ICMP looks "
                "dead to an ICMP-only probe. This cannot be distinguished from a genuinely powered-off "
                "host from one host's data, so treat it as a lead to check, not a confirmed cause."
            ),
            evidence=[
                f"Configured discovery methods: {', '.join(methods)}.",
                "Host was not detected as alive.",
            ],
            remediation=[
                "Add TCP ping probes for common reachable ports (e.g. 22, 80, 135, 139, 443, 445, 3389).",
                "Confirm scanner-to-target ICMP/TCP discovery rules across intervening firewalls.",
            ],
            plugin_ids=[],
            confidence=0.5,
        ))

    # 3. Missing diagnostics: no evidence to even diagnose the discovery failure.
    if not any(host_data.has_plugin(p) for p in (P_SCAN_INFO, P_PING_RESPONSE, P_LAUNCHED)):
        findings.append(Finding(
            category=FindingCategory.MISSING_DIAGNOSTICS,
            severity=Severity.LOW,
            title="Discovery Evidence Missing",
            description=(
                "No scan-info (19506), ping-response (10180), or launched-plugins (112154) data is "
                "present for this host, so there is little to diagnose why discovery failed."
            ),
            evidence=["Host returned no diagnostic plugin output."],
            remediation=[
                "Confirm the host was in scope and the scanner could route to its subnet.",
                "Re-run with debug / launched-plugins enabled to capture discovery detail.",
            ],
            plugin_ids=[],
            confidence=1.0,
        ))

    return findings
