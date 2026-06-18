"""Launched-plugins analyzer — answer "why didn't this plugin run?" carefully.

Uses plugin 112154 ("Enumerate Launched Plugins") to see which plugins actually
ran, and the plugin audit trail (when available) to report *why* a plugin did
not run. A plugin not launching has many innocent causes — dependency not met,
service not detected, OS not applicable, family disabled, safe checks, policy
state — so this analyzer never asserts a problem from non-launch alone. It only
states a cause when the audit trail supplies one; otherwise it presents an
observation and recommends enabling the audit trail to get the reason.

Note: pyTenable's Tenable.io API exposes plugin output but NOT an audit-trail
endpoint, so audit-trail text is consumed only when already present (embedded in
the export or attached), never fetched.
"""

import re

from host_doctor.models import Finding, FindingCategory, HostData, ScanConfig, Severity

P_LAUNCHED_PLUGINS = 112154   # Enumerate Launched Plugins
P_LC_AVAILABLE = 117887       # OS Security Patch Assessment Available

# Categories whose findings indicate "something didn't fully run", i.e. a gap
# where knowing which plugins launched (and why others didn't) adds value.
_GAP_CATEGORIES = {
    FindingCategory.AUTHENTICATION,
    FindingCategory.POLICY,
    FindingCategory.CONFIGURATION,
}

# Plugins whose non-launch is worth surfacing when there's an unresolved gap.
_INTERESTING = {
    P_LC_AVAILABLE: "OS Security Patch Assessment (the credentialed-assessment plugin)",
}


def _parse_launched_plugin_ids(output: str) -> set[int]:
    """Extract plugin IDs from the 112154 output (a list of launched plugins)."""
    ids: set[int] = set()
    for match in re.findall(r"\b(\d{2,6})\b", output or ""):
        ids.add(int(match))
    return ids


def _audit_reason_for(audit_text: str, plugin_id: int) -> str:
    """Return the audit-trail reason line for a plugin, or '' if none/unavailable."""
    if not audit_text:
        return ""
    for line in audit_text.splitlines():
        if str(plugin_id) in line:
            return line.strip()
    return ""


def analyze_launched_plugins(
    host_data: HostData,
    scan_config: ScanConfig,
    prior_findings: list[Finding],
) -> list[Finding]:
    """Enrich an existing diagnostic gap with launched-plugins / audit-trail data.

    This is an enrichment layer, not a primary detector — it only acts when other
    analyzers already flagged a gap, so it never manufactures a finding on its own.
    """
    findings: list[Finding] = []

    has_gap = any(f.category in _GAP_CATEGORIES for f in prior_findings)
    if not has_gap:
        return findings  # nothing unresolved to explain

    launched_output = host_data.get_plugin_output(P_LAUNCHED_PLUGINS)
    # Audit-trail text only if it's already present (never fetched — no API for it).
    audit_text = (host_data.attachments or {}).get("audit_trail", "")

    if launched_output:
        launched = _parse_launched_plugin_ids(launched_output)
        for pid, label in _INTERESTING.items():
            if pid not in launched:
                reason = _audit_reason_for(audit_text, pid)
                if reason:
                    description = (
                        f"Plugin {pid} ({label}) did not launch. Audit trail indicates: {reason}"
                    )
                    remediation = ["Address the cause reported by the audit trail above."]
                else:
                    description = (
                        f"Plugin {pid} ({label}) is not in the launched-plugins list (112154). "
                        "This is an observation, not a diagnosis — a plugin can skip for many "
                        "reasons (unmet dependency, service not detected, OS not applicable, "
                        "family disabled, safe checks, policy state)."
                    )
                    remediation = [
                        "Enable 'Audit Trail Verbosity: All audit trail data' and re-run to get the reason.",
                    ]
                findings.append(Finding(
                    category=FindingCategory.POLICY,
                    severity=Severity.INFO if not audit_text else Severity.MEDIUM,
                    title=f"Plugin {pid} Did Not Launch",
                    description=description,
                    evidence=[f"Launched-plugins list (112154) present; plugin {pid} absent from it."],
                    remediation=remediation,
                    plugin_ids=[P_LAUNCHED_PLUGINS, pid],
                    confidence=1.0 if audit_text else 0.6,
                ))
    else:
        # No launched-plugins list and an unresolved gap -> recommend enabling it.
        findings.append(Finding(
            category=FindingCategory.MISSING_DIAGNOSTICS,
            severity=Severity.INFO,
            title="Enable Launched-Plugins List and Audit Trail",
            description=(
                "To determine exactly which plugins ran and why others did not, re-run with "
                "'Enumerate launched plugins' (plugin 112154) and 'Audit Trail Verbosity: All "
                "audit trail data' enabled. These are debug settings — enable them only for "
                "targeted troubleshooting."
            ),
            evidence=["No plugin 112154 output present in this scan."],
            remediation=[
                "In the scan's Advanced settings, enable 'Enumerate launched plugins'.",
                "Set 'Audit Trail Verbosity' to 'All audit trail data'.",
                "Re-run against this single host and re-analyze.",
            ],
            plugin_ids=[P_LAUNCHED_PLUGINS],
            confidence=1.0,
        ))

    return findings
