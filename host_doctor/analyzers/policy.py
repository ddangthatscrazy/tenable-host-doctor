"""Policy analyzer - check scan configuration vs results."""

from host_doctor.models import Finding, FindingCategory, HostData, ScanConfig, Severity


def analyze_policy(host_data: HostData, scan_config: ScanConfig) -> list[Finding]:
    """Analyze scan policy configuration vs actual results.

    Checks:
    - Plugin family coverage vs detected OS
    - Disabled critical plugin families
    - Safe checks on test environments
    - Scanner/plugin feed staleness

    Args:
        host_data: Host scan results
        scan_config: Scan configuration

    Returns:
        List of policy-related findings
    """
    findings = []

    # Check plugin family coverage vs OS
    os = host_data.operating_system or ""
    os_lower = os.lower()

    expected_families = []
    if "windows" in os_lower:
        expected_families = [
            "Windows",
            "Windows : Microsoft Bulletins",
            "Windows : User management",
        ]
    elif "ubuntu" in os_lower:
        expected_families = ["Ubuntu Local Security Checks"]
    elif "debian" in os_lower:
        expected_families = ["Debian Local Security Checks"]
    elif "centos" in os_lower:
        expected_families = ["CentOS Local Security Checks"]
    elif "red hat" in os_lower or "rhel" in os_lower:
        expected_families = ["Red Hat Local Security Checks"]
    elif "oracle" in os_lower:
        expected_families = ["Oracle Linux Local Security Checks"]
    elif "fedora" in os_lower:
        expected_families = ["Fedora Local Security Checks"]
    elif "linux" in os_lower:
        # Generic Linux — check for any common family
        expected_families = [
            "Red Hat Local Security Checks",
            "Debian Local Security Checks",
            "Ubuntu Local Security Checks",
            "CentOS Local Security Checks",
        ]

    if expected_families:
        # Check against scan_config.enabled_plugin_families (families that ran anywhere
        # in the scan). An empty result from get_vulnerabilities_by_family() doesn't mean
        # the family didn't run — a clean/patched host returns no findings from patch
        # families. Only flag families that never appeared in the scan at all (policy-level
        # disable), not just families with zero findings on this specific host.
        #
        # For generic Linux (unknown distro), ANY one of the candidate families is
        # sufficient — only flag if ALL of them are absent.
        is_generic_linux = os_lower.startswith("linux") and not any(
            d in os_lower for d in ["ubuntu", "debian", "centos", "red hat", "rhel", "oracle", "fedora"]
        )

        if is_generic_linux:
            policy_disabled_families = expected_families if not any(
                f in scan_config.enabled_plugin_families for f in expected_families
            ) else []
        else:
            policy_disabled_families = [
                family for family in expected_families
                if family not in scan_config.enabled_plugin_families
            ]

        if policy_disabled_families:
            finding = Finding(
                category=FindingCategory.POLICY,
                severity=Severity.HIGH,
                title="Plugin Family Disabled in Scan Policy",
                description=(
                    f"Detected OS is '{os}' but critical plugin families were never enabled "
                    "in this scan. These families produced no results across any host."
                ),
                evidence=[
                    f"Detected OS: {os}",
                    f"Policy-disabled families: {', '.join(policy_disabled_families)}",
                    f"Total plugin families active in scan: {len(scan_config.enabled_plugin_families)}",
                ],
                remediation=[
                    "Enable missing plugin families in scan policy",
                    f"For {os}, ensure these families are enabled: {', '.join(expected_families)}",
                    "Consider using 'Advanced Scan' or 'Credentialed Patch Audit' template",
                ],
                plugin_ids=[],
            )
            findings.append(finding)

    # Check safe checks on test/dev environment
    if scan_config.safe_checks_enabled:
        scan_name = scan_config.scan_name or ""
        scan_name_lower = scan_name.lower()

        test_keywords = ["test", "dev", "lab", "staging", "qa"]
        is_test_env = any(keyword in scan_name_lower for keyword in test_keywords)

        if is_test_env:
            finding = Finding(
                category=FindingCategory.CONFIGURATION,
                severity=Severity.MEDIUM,
                title="Safe Checks Enabled on Test Environment",
                description=(
                    "Safe checks are enabled but the scan name suggests this is a test/dev environment. "
                    "Safe checks may miss vulnerabilities that require intrusive testing."
                ),
                evidence=[
                    f"Scan name: {scan_config.scan_name}",
                    "Safe checks: Enabled",
                    f"Scan name contains: {', '.join([k for k in test_keywords if k in scan_name_lower])}",
                ],
                remediation=[
                    "Disable safe checks for test/dev/lab environments",
                    "Safe checks should only be used on production systems",
                    "Allows more thorough vulnerability detection",
                ],
                plugin_ids=[],
            )
            findings.append(finding)

    # Check for no plugin 19506 (scan config info)
    if not host_data.has_plugin(19506):
        finding = Finding(
            category=FindingCategory.CONFIGURATION,
            severity=Severity.LOW,
            title="Missing Scan Configuration Data",
            description=(
                "Plugin 19506 (Nessus Scan Information) was not found in results. "
                "This plugin provides detailed scan configuration for diagnostics."
            ),
            evidence=[
                "Plugin 19506 not found",
                "May be disabled in scan policy",
                "Limits ability to diagnose configuration issues",
            ],
            remediation=[
                "Ensure plugin 19506 is enabled in scan policy",
                "This plugin should always be enabled for troubleshooting",
            ],
            plugin_ids=[19506],
        )
        findings.append(finding)

    # Check for plugin feed staleness (if available)
    if scan_config.plugin_feed_version:
        # Plugin feed format is usually YYYYMMDDHHMMSS
        # Check if it's more than 7 days old
        try:
            feed_date_str = scan_config.plugin_feed_version[:8]  # YYYYMMDD
            from datetime import datetime

            feed_date = datetime.strptime(feed_date_str, "%Y%m%d")
            days_old = (datetime.now() - feed_date).days

            if days_old > 7:
                finding = Finding(
                    category=FindingCategory.CONFIGURATION,
                    severity=Severity.MEDIUM,
                    title="Stale Plugin Feed",
                    description=(
                        f"Plugin feed is {days_old} days old. Tenable releases new plugins daily. "
                        "An outdated plugin feed may miss recent vulnerabilities."
                    ),
                    evidence=[
                        f"Plugin feed version: {scan_config.plugin_feed_version}",
                        f"Feed age: {days_old} days",
                        "Recommended: Update plugins at least weekly",
                    ],
                    remediation=[
                        "Update Nessus scanner to latest plugin feed",
                        "Enable automatic plugin updates",
                        "Verify plugin update schedule in scanner settings",
                    ],
                    plugin_ids=[],
                )
                findings.append(finding)
        except (ValueError, IndexError):
            pass  # Can't parse plugin feed date

    return findings
