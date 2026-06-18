"""Phase 6a: additive failures (DB 91822, integration 122503) and the AdditiveIssue
refactor. The defining property: an additive failure NEVER changes the host verdict,
and additive findings now render WITH their own evidence/plugin_ids (previously lost).
"""

from host_doctor.analyzers.auth import analyze_authentication
from host_doctor.analyzers.credential_state import (
    AdditiveIssue,
    RootCause,
    classify_credential_state,
)
from host_doctor.models import HostData, Plugin, ScanConfig, Severity


def make_host(specs, os="Windows Server 2019"):
    return HostData(
        host_ip="10.0.0.1",
        operating_system=os,
        plugins={pid: Plugin(pid, f"p{pid}", "Settings", 0, plugin_output=out) for pid, out in specs},
    )


def causes(state):
    return [i.cause for i in state.additive]


def issue_for(state, cause):
    return next(i for i in state.additive if i.cause == cause)


# --- DB failure is additive and never masks / is masked by host verdict -------

def test_host_success_plus_db_failure_keeps_success_verdict():
    # 117887 = host local checks ran (SUCCESS); 91822 = DB creds failed.
    host = make_host([(117887, "Local checks enabled"), (91822, "DB auth failed")])
    state = classify_credential_state(host)
    assert state.root_cause == RootCause.SUCCESS           # host verdict unchanged
    assert RootCause.DATABASE_AUTH_FAILURE in causes(state)  # but DB failure surfaced


def test_db_failure_carries_its_own_evidence_and_pid():
    host = make_host([(117887, "ok"), (91822, "DB auth failed")])
    issue = issue_for(classify_credential_state(host), RootCause.DATABASE_AUTH_FAILURE)
    assert issue.plugin_ids == [91822]
    assert issue.evidence and "database" in issue.evidence[0].lower()
    assert issue.severity == Severity.HIGH
    assert issue.protocol == "database"


def test_db_failure_coexists_with_host_failure():
    # Host has NO credentials (110723) AND a DB failure — both must be reported.
    host = make_host([(110723, "Protocol : SSH\nNo credentials provided."), (91822, "DB fail")])
    state = classify_credential_state(host)
    assert state.root_cause == RootCause.NO_CREDENTIALS_PROVIDED   # host verdict intact
    assert RootCause.DATABASE_AUTH_FAILURE in causes(state)


# --- Integration failure ------------------------------------------------------

def test_integration_failure_is_additive_medium():
    host = make_host([(117887, "ok"), (122503, "integration auth failed")])
    state = classify_credential_state(host)
    assert state.root_cause == RootCause.SUCCESS
    issue = issue_for(state, RootCause.INTEGRATION_AUTH_FAILURE)
    assert issue.plugin_ids == [122503]
    assert issue.severity == Severity.MEDIUM


# --- Rendering: additive findings now carry evidence/plugin_ids (the bug fix) --

def test_rendered_db_finding_has_evidence_and_pid():
    host = make_host([(117887, "ok"), (91822, "DB fail")])
    findings = analyze_authentication(host, ScanConfig())
    db = next(f for f in findings if f.title.startswith("Database Authentication Failed"))
    assert db.severity == Severity.HIGH
    assert db.evidence            # previously additive findings rendered with []
    assert 91822 in db.plugin_ids
    assert "(DATABASE)" in db.title


def test_regression_privilege_additive_now_carries_evidence():
    # Before the refactor, additive findings lost their evidence/plugin_ids.
    host = make_host([(117887, "ok"), (24786, "Not admin")])
    findings = analyze_authentication(host, ScanConfig())
    priv = next(f for f in findings if f.title == "Authenticated but Under-Privileged")
    assert priv.evidence          # the fix: evidence is no longer stripped
    assert 24786 in priv.plugin_ids
    # And the host verdict is still SUCCESS (refactor is behavior-preserving),
    # rendered alongside the additive caveat.
    assert any(f.title == "Credentialed Assessment Succeeded" for f in findings)
    state = classify_credential_state(host)
    assert state.root_cause == RootCause.SUCCESS
