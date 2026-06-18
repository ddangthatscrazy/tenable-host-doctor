"""Credential-state classifier — the single source of truth for auth diagnosis.

Resolves a host onto two independent axes plus a connectivity gate, then returns
one disambiguated root cause. Both auth.py and coverage.py consume this rather
than re-deriving state from raw plugins, which keeps verdicts consistent and the
precedence order enforced in exactly one place.

Axis A (authentication): from the "Target Credential Status by Authentication
Protocol" family, per protocol — none / failed / intermittent / valid.
Axis B (local checks ran?): from the "OS Security Patch Assessment" family —
ran (117887) vs did not (21745 / 117886 / 110695).

The load-bearing rule: Axis B failing (21745) does NOT imply Axis A failed.
21745 is an umbrella ("Local Checks Not Run"); authentication is only one of
several causes (connectivity, sockets, unsupported OS). We only call something a
credential failure when 104410 corroborates it.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum

from host_doctor.models import HostData, Severity

# --- Plugin IDs (labels verified against the Tenable plugin database) ----------
P_SCAN_INFO = 19506          # Nessus Scan Information
P_LC_AVAILABLE = 117887      # OS Security Patch Assessment Available  -> authoritative success
P_LC_NOT_AVAILABLE = 117886  # OS Security Patch Assessment Not Available (informational)
P_LC_NOT_SUPPORTED = 110695  # OS Security Patch Assessment Checks Not Supported (OS unsupported)
P_LC_FAILED = 21745          # Authentication Failure - Local Checks Not Run (umbrella)
P_CRED_NONE = 110723         # Target Credential Status - No Credentials Provided
P_CRED_FAILURE = 104410      # Target Credential Status - Failure for Provided Credentials
P_CRED_VALID = 141118        # Target Credential Status - Valid Credentials Provided
P_CRED_NO_ISSUES = 110095    # Target Credential Issues - No Issues Found
P_CRED_INTERMITTENT = 117885  # Target Credential Issues - Intermittent Authentication Failure
P_PRIV_INSUFFICIENT = 110385  # Target Credential Issues - Insufficient Privilege
P_SSH_PRIV_ESCALATION = 102094  # SSH Commands Require Privilege Escalation (NOT a success signal)
P_WIN_NOT_ADMIN = 24786      # Nessus Windows Scan Not Performed with Admin Privileges
P_WIN_REGISTRY = 26917       # Nessus Cannot Access the Windows Registry
P_WIN_REG_START = 35705      # SMB Registry: Starting the Registry Service failed
P_WIN_REG_STOP = 35706       # SMB Registry: Stopping the Registry Service failed
P_WIN_REG_PARTIAL = 10428    # SMB Registry Not Fully Accessible (partial access)
P_DB_AUTH_FAIL = 91822       # Database Authentication Failure(s) for Provided Credentials
P_INTEGRATION_FAIL = 122503  # Integration Credential Status - Failure for Provided Credentials
P_SSH_RATE_LIMIT = 122501    # SSH Rate Limited Device
# Discovery-RESPONSE plugins: their PRESENCE proves the host answered discovery.
# (Non-response is signaled by their absence, never by their presence.)
P_PING_REPLY = 10180         # Ping the remote host (host responded to discovery)
P_ICMP_TIMESTAMP = 10114     # ICMP Timestamp Request Remote Date Disclosure (host responded)

DISCOVERY_RESPONSE_PLUGINS = {P_PING_REPLY, P_ICMP_TIMESTAMP}

# Plugins proving the host was actually assessed (not merely pinged).
ASSESSMENT_PLUGINS = {
    P_SCAN_INFO, P_LC_AVAILABLE, P_LC_NOT_AVAILABLE, P_LC_NOT_SUPPORTED,
    P_LC_FAILED, P_CRED_NONE, P_CRED_FAILURE, P_CRED_VALID,
    P_CRED_NO_ISSUES, P_CRED_INTERMITTENT,
}

# OS-patch families whose presence proves credentialed local checks ran.
PATCH_FAMILIES = (
    "Local Security Checks",          # matches every "<OS> Local Security Checks"
    "Microsoft Bulletins",
)

# Text in a 21745 body that means "couldn't connect" rather than "creds wrong".
_SOCKET_RE = re.compile(
    r"unable to (create a socket|connect)"
    r"|connection (refused|timed out|reset)"
    r"|no route to host|could not connect|tcp handshake",
    re.IGNORECASE,
)


class RootCause(str, Enum):
    SUCCESS = "success"                              # 117887 / patch families present
    INSUFFICIENT_PRIVILEGE = "insufficient_privilege"  # authenticated, under-privileged
    REGISTRY_INACCESSIBLE = "registry_inaccessible"  # Windows registry blocked
    REGISTRY_PARTIAL_ACCESS = "registry_partial_access"  # additive: registry reachable but partial (10428)
    DATABASE_AUTH_FAILURE = "database_auth_failure"   # additive: DB creds failed (91822)
    INTEGRATION_AUTH_FAILURE = "integration_auth_failure"  # additive: integration creds failed (122503)
    NO_CREDENTIALS_PROVIDED = "no_credentials_provided"  # 110723 — config gap
    CREDENTIAL_FAILURE = "credential_failure"        # 104410 — creds wrong
    INTERMITTENT_AUTH = "intermittent_auth"          # 117885 — lockout / rate-limit
    CONNECTIVITY_DURING_AUTH = "connectivity_during_auth"  # 21745 socket text, no 104410
    NETWORK_UNREACHABLE = "network_unreachable"      # only connectivity plugins
    LOCAL_CHECKS_FAILED_OTHER = "local_checks_failed_other"  # 21745, non-auth/non-socket
    INDETERMINATE = "indeterminate"                  # insufficient evidence
    AGENT_NO_DATA = "agent_no_data"                  # agent scan returned no assessment data


@dataclass
class AdditiveIssue:
    """A secondary issue that coexists with the primary verdict, carrying its own
    evidence so it renders fully (not stripped). `severity=None` means render with
    the cause's default severity; `protocol` annotates the affected layer."""

    cause: RootCause
    evidence: list[str] = field(default_factory=list)
    plugin_ids: list[int] = field(default_factory=list)
    severity: Severity | None = None
    protocol: str = ""


@dataclass
class CredentialState:
    """Result of classification. `additive` causes coexist with the primary verdict."""

    root_cause: RootCause
    protocol: str = ""                          # "ssh" | "smb" | ""
    evidence: list[str] = field(default_factory=list)
    additive: list[AdditiveIssue] = field(default_factory=list)
    confidence: float = 1.0                     # 1.0 authoritative, lower = inferred
    plugin_ids: list[int] = field(default_factory=list)

    @property
    def authenticated(self) -> bool:
        """Did at least one protocol authenticate (even if degraded)?"""
        return self.root_cause in (
            RootCause.SUCCESS,
            RootCause.INSUFFICIENT_PRIVILEGE,
            RootCause.REGISTRY_INACCESSIBLE,
        )


def _detect_protocol(body: str) -> str:
    b = body.lower()
    if "protocol : ssh" in b or "protocol        : ssh" in b or "port : 22" in b:
        return "ssh"
    if "protocol : smb" in b or "smb" in b or "windows" in b:
        return "smb"
    return ""


def _has_patch_families(host_data: HostData) -> bool:
    for vuln in host_data.vulnerabilities:
        fam = vuln.family or ""
        if any(marker in fam for marker in PATCH_FAMILIES):
            return True
    return False


def _collect_additive(host_data: HostData) -> list[AdditiveIssue]:
    """Issues that can coexist with any primary verdict, each carrying its own
    evidence/plugin_ids so it renders fully. These never alter the primary
    verdict — e.g. a host can pass OS auth (SUCCESS) yet fail database auth."""
    has = host_data.has_plugin
    issues: list[AdditiveIssue] = []

    # Privilege (authenticated but under-privileged).
    if has(P_WIN_NOT_ADMIN) or has(P_PRIV_INSUFFICIENT) or has(P_SSH_PRIV_ESCALATION):
        ev: list[str] = []
        pids: list[int] = []
        if has(P_WIN_NOT_ADMIN):
            ev.append(f"Plugin {P_WIN_NOT_ADMIN}: Windows account lacks administrator privileges.")
            pids.append(P_WIN_NOT_ADMIN)
        if has(P_PRIV_INSUFFICIENT):
            ev.append(f"Plugin {P_PRIV_INSUFFICIENT}: authenticated but insufficient privilege for some checks.")
            pids.append(P_PRIV_INSUFFICIENT)
        if has(P_SSH_PRIV_ESCALATION):
            ev.append(f"Plugin {P_SSH_PRIV_ESCALATION}: SSH commands failed needing privilege escalation (sudo/su).")
            pids.append(P_SSH_PRIV_ESCALATION)
        issues.append(AdditiveIssue(RootCause.INSUFFICIENT_PRIVILEGE, evidence=ev, plugin_ids=pids))

    # Registry. Full denial (26917 / service start-stop failures) supersedes the
    # softer "partially accessible" signal (10428) so they never double-report.
    full_denial = [p for p in (P_WIN_REGISTRY, P_WIN_REG_START, P_WIN_REG_STOP) if has(p)]
    if full_denial:
        issues.append(AdditiveIssue(
            RootCause.REGISTRY_INACCESSIBLE,
            evidence=["Windows registry not fully accessible (Remote Registry service / UAC token filtering / GPO)."],
            plugin_ids=full_denial,
        ))
    elif has(P_WIN_REG_PARTIAL):
        issues.append(AdditiveIssue(
            RootCause.REGISTRY_PARTIAL_ACCESS,
            evidence=[f"Plugin {P_WIN_REG_PARTIAL}: registry is reachable but not fully accessible; some registry-based checks may be incomplete."],
            plugin_ids=[P_WIN_REG_PARTIAL],
            severity=Severity.LOW,
        ))

    # Database credential failure (separate from host SSH/SMB auth — can coexist
    # with a host SUCCESS verdict and must never be masked by it).
    if has(P_DB_AUTH_FAIL):
        issues.append(AdditiveIssue(
            RootCause.DATABASE_AUTH_FAILURE,
            evidence=[f"Plugin {P_DB_AUTH_FAIL}: database authentication failed for the provided database credentials."],
            plugin_ids=[P_DB_AUTH_FAIL],
            severity=Severity.HIGH,
            protocol="database",
        ))

    # Integration credential failure (patch-management / connector creds — distinct
    # from host credentials; failure here does not block host assessment).
    if has(P_INTEGRATION_FAIL):
        issues.append(AdditiveIssue(
            RootCause.INTEGRATION_AUTH_FAILURE,
            evidence=[f"Plugin {P_INTEGRATION_FAIL}: integration authentication failed for the provided integration credentials."],
            plugin_ids=[P_INTEGRATION_FAIL],
            severity=Severity.MEDIUM,
            protocol="integration",
        ))

    return issues


def classify_credential_state(host_data: HostData, scan_config=None) -> CredentialState:
    """Resolve a host to a single disambiguated credential/local-checks verdict.

    When scan_config indicates an agent scan, uses agent-specific logic: agents
    are inherently credentialed and perform no network/remote checks, so the
    scanner-oriented verdicts (no-credentials, credential-failure, connectivity,
    unreachable) don't apply. scan_config=None preserves the original scanner
    behavior exactly.
    """
    has = host_data.has_plugin
    out = lambda pid: host_data.get_plugin_output(pid) or ""  # noqa: E731

    additive = _collect_additive(host_data)

    # --- Agent scans: short-circuit to agent-specific logic ---
    sensor_type = getattr(scan_config, "sensor_type", None) if scan_config else None
    if sensor_type == "agent":
        return _classify_agent(host_data, additive)

    # --- Gate: did the host respond at all? ---
    # A host that produced discovery-response plugins, assessment plugins, or any
    # vulnerability data demonstrably responded. Only call it unreachable when the
    # parser flagged it unreachable AND there is no response evidence of any kind.
    has_response = (
        any(has(p) for p in DISCOVERY_RESPONSE_PLUGINS)
        or any(has(p) for p in ASSESSMENT_PLUGINS)
        or bool(host_data.vulnerabilities)
    )
    if not host_data.is_reachable and not has_response:
        return CredentialState(
            RootCause.NETWORK_UNREACHABLE,
            evidence=["No discovery, assessment, or vulnerability data was produced for this host."],
        )

    # --- Axis B (authoritative): did local checks run? ---
    if has(P_LC_AVAILABLE) or _has_patch_families(host_data):
        ev = []
        if has(P_LC_AVAILABLE):
            ev.append(f"Plugin {P_LC_AVAILABLE}: local checks ran (credentialed assessment OK).")
        else:
            ev.append("OS patch-assessment families present: credentialed local checks ran.")
        state = CredentialState(RootCause.SUCCESS, evidence=ev, plugin_ids=[P_LC_AVAILABLE] if has(P_LC_AVAILABLE) else [])
        state.additive = additive
        return state

    # --- Local checks did NOT run -> find out why, in strict precedence order ---

    # 1. No creds provided (config gap, not a failure)
    if has(P_CRED_NONE):
        s = CredentialState(
            RootCause.NO_CREDENTIALS_PROVIDED,
            protocol=_detect_protocol(out(P_CRED_NONE)),
            evidence=[f"Plugin {P_CRED_NONE}: auth-capable ports found but no credentials were provided in the policy."],
            plugin_ids=[P_CRED_NONE],
        )

    # 2. Creds provided and failed
    elif has(P_CRED_FAILURE):
        body = out(P_CRED_FAILURE)
        proto = _detect_protocol(body)
        ev = [f"Plugin {P_CRED_FAILURE}: login failed for provided credentials."]
        if proto == "ssh" and has(P_SSH_RATE_LIMIT):
            ev.append(f"Plugin {P_SSH_RATE_LIMIT}: SSH rate limiting detected (likely the real cause).")
        s = CredentialState(RootCause.CREDENTIAL_FAILURE, protocol=proto, evidence=ev, plugin_ids=[P_CRED_FAILURE])

    # 3. Intermittent (authenticated, then later failed)
    elif has(P_CRED_INTERMITTENT):
        s = CredentialState(
            RootCause.INTERMITTENT_AUTH,
            protocol=_detect_protocol(out(P_CRED_INTERMITTENT)),
            evidence=[f"Plugin {P_CRED_INTERMITTENT}: intermittent auth — lockout, rate-limit, or unstable link."],
            plugin_ids=[P_CRED_INTERMITTENT],
        )

    # 4. 21745 present but NO 104410 corroboration -> disambiguate by body text.
    #    THIS is the false-positive trap the old logic fell into (21745 == "auth failed").
    elif has(P_LC_FAILED):
        body = out(P_LC_FAILED)
        if _SOCKET_RE.search(body):
            s = CredentialState(
                RootCause.CONNECTIVITY_DURING_AUTH,
                confidence=0.9,
                evidence=[
                    f"Plugin {P_LC_FAILED}: socket/connection error in body — this is a NETWORK issue, not credentials.",
                    "No plugin 104410 (credential failure) present to corroborate an auth problem.",
                ],
                plugin_ids=[P_LC_FAILED],
            )
        else:
            s = CredentialState(
                RootCause.LOCAL_CHECKS_FAILED_OTHER,
                confidence=0.7,
                evidence=[f"Plugin {P_LC_FAILED}: local checks failed for a non-auth, non-socket reason. Inspect the body."],
                plugin_ids=[P_LC_FAILED],
            )

    # 5. Informational "not available / not supported"
    elif has(P_LC_NOT_AVAILABLE) or has(P_LC_NOT_SUPPORTED):
        pid = P_LC_NOT_SUPPORTED if has(P_LC_NOT_SUPPORTED) else P_LC_NOT_AVAILABLE
        s = CredentialState(
            RootCause.LOCAL_CHECKS_FAILED_OTHER,
            confidence=0.6,
            evidence=[f"Plugin {pid}: local checks not enabled for an informational reason (e.g. OS unsupported for local checks)."],
            plugin_ids=[pid],
        )

    # 6. Nothing decisive — usually plugin debugging was off / sparse export.
    else:
        s = CredentialState(
            RootCause.INDETERMINATE,
            confidence=0.3,
            evidence=[
                "No authoritative credential-status or local-check plugins present.",
                "Re-run with plugin debugging enabled (see the diagnostic scan generator) to populate 84239 and the credential-status family.",
            ],
        )

    # Attach additive issues (they carry their own evidence) to the primary verdict.
    s.additive = additive
    return s


def _classify_agent(host_data, additive) -> CredentialState:
    """Agent-specific classification.

    Agents are installed on the asset and already have the access needed for
    local security checks, so they use no managed credentials and perform no
    network/remote checks. That makes the scanner verdicts (no-credentials,
    credential-failure, connectivity, unreachable) inapplicable. The only
    questions for an agent scan are: did local checks run, fail, or produce
    nothing?
    """
    has = host_data.has_plugin

    if has(P_LC_AVAILABLE) or _has_patch_families(host_data):
        s = CredentialState(
            RootCause.SUCCESS,
            evidence=["Agent scan: local checks ran (agents are inherently credentialed)."],
            plugin_ids=[P_LC_AVAILABLE] if has(P_LC_AVAILABLE) else [],
        )
    elif has(P_LC_FAILED):
        s = CredentialState(
            RootCause.LOCAL_CHECKS_FAILED_OTHER,
            confidence=0.7,
            evidence=[
                f"Agent scan: plugin {P_LC_FAILED} indicates local checks failed to run "
                "(an OS/plugin reason — agents don't have managed-credential failures).",
            ],
            plugin_ids=[P_LC_FAILED],
        )
    else:
        s = CredentialState(
            RootCause.AGENT_NO_DATA,
            confidence=0.5,
            evidence=[
                "Agent scan returned no patch-assessment or local-check data.",
                "Agents use no managed credentials and run no network checks, so "
                "credential and connectivity diagnoses do not apply here.",
            ],
        )

    s.additive = additive
    return s
