"""Data models for Host Doctor."""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Optional


class Severity(str, Enum):
    """Finding severity levels."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class FindingCategory(str, Enum):
    """Categories of diagnostic findings."""

    AUTHENTICATION = "authentication"
    NETWORK = "network"
    CONFIGURATION = "configuration"
    POLICY = "policy"
    PERFORMANCE = "performance"
    MISSING_DIAGNOSTICS = "missing_diagnostics"


@dataclass
class Plugin:
    """Nessus plugin information."""

    plugin_id: int
    plugin_name: str
    family: str
    severity: int
    output: Optional[str] = None
    plugin_output: Optional[str] = None  # Raw plugin output text


@dataclass
class Vulnerability:
    """Vulnerability found on host."""

    plugin_id: int
    plugin_name: str
    family: str
    severity: int
    count: int = 1
    port: Optional[int] = None
    protocol: Optional[str] = None
    plugin_output: Optional[str] = None


@dataclass
class HostData:
    """Complete host scan data."""

    host_ip: str
    hostname: Optional[str] = None
    operating_system: Optional[str] = None
    mac_address: Optional[str] = None
    netbios_name: Optional[str] = None
    host_start: Optional[datetime] = None
    host_end: Optional[datetime] = None

    # Scan results
    vulnerabilities: list[Vulnerability] = field(default_factory=list)
    plugins: dict[int, Plugin] = field(default_factory=dict)

    # Status flags
    is_reachable: bool = True
    scan_completed: bool = True

    # Timing
    scan_duration_seconds: Optional[float] = None

    # Historical data (from .kb file if available)
    historical_data: Optional[dict[str, Any]] = None

    # Attachments from API (debug logs, etc.)
    attachments: dict[str, str] = field(default_factory=dict)

    def get_plugin_output(self, plugin_id: int) -> Optional[str]:
        """Get plugin output text by ID."""
        plugin = self.plugins.get(plugin_id)
        return plugin.plugin_output if plugin else None

    def has_plugin(self, plugin_id: int) -> bool:
        """Check if plugin ran on this host."""
        return plugin_id in self.plugins

    def get_vulnerabilities_by_family(self, family: str) -> list[Vulnerability]:
        """Get all vulnerabilities from a specific plugin family."""
        return [v for v in self.vulnerabilities if v.family == family]


@dataclass
class ScanConfig:
    """Scan configuration extracted from scan data."""

    scan_id: Optional[int] = None
    scan_name: Optional[str] = None
    scan_uuid: Optional[str] = None
    policy_name: Optional[str] = None
    scanner_name: Optional[str] = None
    scan_start: Optional[datetime] = None
    scan_end: Optional[datetime] = None
    history_id: Optional[int] = None  # For API attachment fetching

    # Configuration details (from plugin 19506)
    nessus_version: Optional[str] = None
    plugin_feed_version: Optional[str] = None
    safe_checks_enabled: Optional[bool] = None
    port_range: Optional[str] = None
    max_checks_per_host: Optional[int] = None
    network_timeout: Optional[int] = None

    # Enhanced config data (from plugin 19506)
    ping_rtt_ms: Optional[float] = None  # Network latency
    port_scanner_type: Optional[str] = None  # e.g., "wmi_netstat", "syn"
    thorough_tests: Optional[bool] = None
    experimental_tests: Optional[bool] = None
    paranoia_level: Optional[int] = None
    debugging_enabled: Optional[bool] = None
    debugging_level: Optional[int] = None
    optimize_tests: Optional[bool] = None
    report_verbosity: Optional[int] = None

    # Credential configuration
    has_windows_creds: bool = False
    has_ssh_creds: bool = False
    has_snmp_creds: bool = False
    credential_used: Optional[str] = None  # e.g., "domain\user"
    credential_protocol: Optional[str] = None  # e.g., "SMB", "SSH"

    # Plugin families
    enabled_plugin_families: list[str] = field(default_factory=list)
    disabled_plugin_families: list[str] = field(default_factory=list)

    # Raw plugin 19506 output
    scan_config_output: Optional[str] = None


@dataclass
class Finding:
    """Diagnostic finding about why host scan failed/incomplete."""

    category: FindingCategory
    severity: Severity
    title: str
    description: str
    evidence: list[str] = field(default_factory=list)
    remediation: list[str] = field(default_factory=list)

    # Technical details
    plugin_ids: list[int] = field(default_factory=list)
    config_issues: dict[str, Any] = field(default_factory=dict)

    # LLM enhancement (optional)
    llm_narrative: Optional[str] = None  # Root cause explanation from LLM analysis


@dataclass
class DiagnosticReport:
    """Complete diagnostic report for a single host."""

    host_ip: str
    scan_name: str
    generated_at: datetime

    # Data sources used
    nessus_file: str
    nessus_db_used: bool = False
    kb_file_used: bool = False

    # Analysis results
    findings: list[Finding] = field(default_factory=list)
    host_data: Optional[HostData] = None
    scan_config: Optional[ScanConfig] = None

    # Summary
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    info_count: int = 0

    # Recommendations
    needs_diagnostic_scan: bool = False
    diagnostic_scan_config: Optional[dict[str, Any]] = None

    def __post_init__(self):
        """Calculate summary counts."""
        for finding in self.findings:
            if finding.severity == Severity.CRITICAL:
                self.critical_count += 1
            elif finding.severity == Severity.HIGH:
                self.high_count += 1
            elif finding.severity == Severity.MEDIUM:
                self.medium_count += 1
            elif finding.severity == Severity.LOW:
                self.low_count += 1
            elif finding.severity == Severity.INFO:
                self.info_count += 1

    def get_findings_by_category(self, category: FindingCategory) -> list[Finding]:
        """Get all findings in a specific category."""
        return [f for f in self.findings if f.category == category]

    def get_findings_by_severity(self, severity: Severity) -> list[Finding]:
        """Get all findings at a specific severity level."""
        return [f for f in self.findings if f.severity == severity]
