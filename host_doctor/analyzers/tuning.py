"""Scan-tuning analyzer — explain a slow scan from its configuration.

Turns the tuning settings the parser already extracts from plugin 19506 into
"why your scan was slow, and how to tune it" observations. These are advisory
(INFO / Performance), not problems.

Discipline:
- Only emit for settings actually present in the parsed config (never guess).
- Gate on the scan being slow (or its duration unknown) so we don't nag about
  heavy settings on a scan that completed quickly.
- For compliance, follow the guide: authority audits (CIS/DISA) don't move scan
  time much; it's FILE CONTENT checks that do. So only raise compliance as a
  speed factor on a slow scan, and phrase it as "if your audits include file
  content checks" rather than blaming compliance broadly.
"""

from host_doctor.models import Finding, FindingCategory, HostData, ScanConfig, Severity

# A scan slower than this (seconds) is worth tuning advice. Below it, heavy
# settings clearly aren't causing a problem, so stay quiet.
SLOW_SCAN_SECONDS = 600

# Network timeout (s) above this is notably elevated (default is ~5).
ELEVATED_TIMEOUT_SECONDS = 10


def _tuning(title: str, description: str, *remediation: str) -> Finding:
    return Finding(
        category=FindingCategory.PERFORMANCE,
        severity=Severity.INFO,
        title=title,
        description=description,
        evidence=[],
        remediation=list(remediation),
        plugin_ids=[19506],
    )


def analyze_scan_tuning(host_data: HostData, scan_config: ScanConfig) -> list[Finding]:
    """Emit tuning observations explaining a slow scan, from its configuration."""
    findings: list[Finding] = []

    duration = host_data.scan_duration_seconds
    # Quiet on fast scans; advise when slow or when duration is unknown.
    if duration is not None and duration <= SLOW_SCAN_SECONDS:
        return findings

    is_agent = getattr(scan_config, "sensor_type", None) == "agent"

    # Thorough tests — the guide explicitly notes this increases scan time.
    if scan_config.thorough_tests:
        findings.append(_tuning(
            "Thorough Tests Enabled",
            "'Perform thorough tests' is on, which makes plugins work harder (e.g. deeper "
            "SMB share traversal) and increases scan time.",
            "Disable 'Perform thorough tests' if scan speed matters more than maximum depth.",
        ))

    # Experimental tests.
    if scan_config.experimental_tests:
        findings.append(_tuning(
            "Experimental Tests Enabled",
            "Experimental tests are enabled, which can add scan time for limited benefit.",
            "Disable experimental tests unless you specifically need them.",
        ))

    # Test optimization off — Nessus skips its usual "don't run inapplicable plugins" pass.
    if scan_config.optimize_tests is False:
        findings.append(_tuning(
            "Test Optimization Disabled",
            "'Optimize the test' is off, so Nessus runs plugins it could otherwise skip, "
            "increasing scan time.",
            "Re-enable test optimization unless you have a specific reason to disable it.",
        ))

    # Elevated network timeout — impacts every check that relies on a timeout.
    if scan_config.network_timeout and scan_config.network_timeout > ELEVATED_TIMEOUT_SECONDS:
        findings.append(_tuning(
            "Elevated Network Timeout",
            f"Network timeout is set to {scan_config.network_timeout}s (default is ~5s). This "
            "applies to every timeout-dependent check and can increase scan time substantially.",
            "Lower the network timeout unless you are scanning over a genuinely slow link.",
        ))

    # UDP port scanning — scanner-only; the guide warns it can dramatically increase time.
    if not is_agent:
        pst = (scan_config.port_scanner_type or "").lower()
        pr = (scan_config.port_range or "").lower()
        if "udp" in pst or "u:" in pr:
            findings.append(_tuning(
                "UDP Port Scanning Enabled",
                "UDP port scanning is enabled. Per Tenable, this can dramatically increase scan "
                "time and produce unreliable results.",
                "Disable the UDP port scanner unless you specifically need UDP coverage.",
                "Prefer local port enumeration (netstat/SNMP) where possible.",
            ))

    # Compliance / file-content audits — only on a slow scan, phrased per the guide:
    # authority audits (CIS/DISA) are cheap; FILE CONTENT checks are the expensive ones.
    families = {(v.family or "") for v in host_data.vulnerabilities}
    if any("compliance" in f.lower() for f in families):
        findings.append(_tuning(
            "Compliance Auditing May Be Slowing the Scan",
            "This scan ran compliance audits and was slow. Most authority-based audits "
            "(CIS/DISA) have little runtime impact, so this is only a likely cause IF the "
            "policy includes File Content audits, which are the expensive ones. Host Doctor "
            "cannot tell from the export which audit types are enabled, so treat this as a "
            "lead to check, not a confirmed cause.",
            "Check whether the policy includes File Content audits; if so, narrow their scope (paths/patterns).",
            "Otherwise, compliance auditing is unlikely to be the main slowdown — look at the other tuning items.",
        ))

    return findings
