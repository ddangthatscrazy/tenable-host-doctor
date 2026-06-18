"""Validation analyzer — flags conditions that make scan RESULTS unreliable even
when the scan itself authenticated and ran fine.

Currently: a pending Windows Update reboot (plugin 35453). This isn't a scan
failure — the host scanned successfully — but the patch-assessment results can be
stale until the reboot completes, so the report should say so.
"""

from host_doctor.models import Finding, FindingCategory, HostData, ScanConfig, Severity

P_REBOOT_REQUIRED = 35453  # Microsoft Windows Update Reboot Required


def analyze_validation(host_data: HostData, scan_config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []

    if host_data.has_plugin(P_REBOOT_REQUIRED):
        findings.append(Finding(
            category=FindingCategory.CONFIGURATION,
            severity=Severity.MEDIUM,
            title="Pending Reboot May Affect Patch Results",
            description=(
                f"Plugin {P_REBOOT_REQUIRED} reports a pending Windows Update reboot. Patch-assessment "
                "results can be unreliable until the host reboots: installed updates may not be in "
                "effect and superseded-patch logic can be misreported. Framed here as scan-result "
                "freshness; note that Tenable rates this plugin High because the host can remain "
                "vulnerable until the reboot completes."
            ),
            evidence=[f"Plugin {P_REBOOT_REQUIRED}: Microsoft Windows Update Reboot Required."],
            remediation=[
                "Reboot the host to apply pending updates, then re-scan for an accurate patch state.",
                "Until then, treat this scan's patch findings as provisional.",
            ],
            plugin_ids=[P_REBOOT_REQUIRED],
            confidence=1.0,
        ))

    return findings
