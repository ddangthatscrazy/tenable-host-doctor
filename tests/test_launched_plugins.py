"""Phase 4: launched-plugins / audit-trail analyzer.

Key discipline: non-launch is an OBSERVATION, never a problem, unless the audit
trail supplies a reason.
"""

from host_doctor.analyzers.launched_plugins import (
    analyze_launched_plugins,
    _parse_launched_plugin_ids,
)
from host_doctor.models import (
    Finding,
    FindingCategory,
    HostData,
    Plugin,
    ScanConfig,
    Severity,
)


def gap_finding():
    return Finding(
        category=FindingCategory.AUTHENTICATION, severity=Severity.HIGH,
        title="Credential Authentication Failed", description="x",
    )


def host_with_launched(output, attachments=None):
    return HostData(
        host_ip="10.0.0.1",
        plugins={112154: Plugin(112154, "launched", "Settings", 0, plugin_output=output)},
        attachments=attachments or {},
    )


# --- parsing ------------------------------------------------------------------

def test_parse_launched_ids():
    ids = _parse_launched_plugin_ids("Launched: 19506, 10180, 141118")
    assert {19506, 10180, 141118} <= ids


# --- enrichment only fires when there's a prior gap ---------------------------

def test_no_gap_means_no_findings():
    host = host_with_launched("19506")
    assert analyze_launched_plugins(host, ScanConfig(), prior_findings=[]) == []


# --- 112154 present, expected plugin absent, NO audit trail -> observation ----

def test_missing_plugin_without_audit_is_informational_observation():
    # 117887 (patch assessment) not in the launched list, and a gap exists.
    host = host_with_launched("19506, 10180")  # no 117887
    findings = analyze_launched_plugins(host, ScanConfig(), [gap_finding()])
    assert len(findings) == 1
    f = findings[0]
    assert f.severity == Severity.INFO            # observation, not a problem
    assert "observation, not a diagnosis" in f.description
    assert f.confidence < 1.0


# --- 112154 present, expected plugin absent, WITH audit trail -> asserts cause -

def test_missing_plugin_with_audit_asserts_reason():
    host = host_with_launched(
        "19506, 10180",
        attachments={"audit_trail": "Plugin 117887 not launched: dependency 12634 failed"},
    )
    findings = analyze_launched_plugins(host, ScanConfig(), [gap_finding()])
    assert len(findings) == 1
    f = findings[0]
    assert f.severity == Severity.MEDIUM
    assert "Audit trail indicates" in f.description
    assert f.confidence == 1.0


# --- expected plugin present -> no finding ------------------------------------

def test_present_plugin_no_finding():
    host = host_with_launched("19506, 117887, 10180")  # 117887 launched
    assert analyze_launched_plugins(host, ScanConfig(), [gap_finding()]) == []


# --- no 112154 + a gap -> recommend enabling it -------------------------------

def test_no_launched_list_recommends_enabling():
    host = HostData(host_ip="10.0.0.1", plugins={})  # no 112154
    findings = analyze_launched_plugins(host, ScanConfig(), [gap_finding()])
    assert len(findings) == 1
    assert findings[0].category == FindingCategory.MISSING_DIAGNOSTICS
    assert "Enumerate launched plugins" in " ".join(findings[0].remediation)
