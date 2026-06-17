"""Analyzer for debug logs and attachments.

This analyzer extracts useful diagnostic information from plugin debug logs,
particularly SSH command execution logs and authentication details.
"""

import re
from typing import Optional

from host_doctor.models import (
    Finding,
    FindingCategory,
    HostData,
    ScanConfig,
    Severity,
)


def analyze_debug_logs(
    host_data: HostData,
    scan_config: ScanConfig,
) -> list[Finding]:
    """Analyze debug logs for authentication and execution details.

    Args:
        host_data: Host scan data with attachments
        scan_config: Scan configuration

    Returns:
        List of findings extracted from debug logs
    """
    findings = []

    # Check if debug logs are available
    if not host_data.attachments.get("debug_logs"):
        return findings

    debug_logs = host_data.attachments["debug_logs"]

    # Parse SSH command logs
    ssh_findings = _parse_ssh_commands(debug_logs, host_data)
    findings.extend(ssh_findings)

    # Parse authentication attempts
    auth_findings = _parse_auth_attempts(debug_logs, host_data)
    findings.extend(auth_findings)

    # Parse plugin errors
    error_findings = _parse_plugin_errors(debug_logs, host_data)
    findings.extend(error_findings)

    return findings


def _parse_ssh_commands(debug_logs: str, host_data: HostData) -> list[Finding]:
    """Extract SSH commands executed during the scan.

    Args:
        debug_logs: Raw debug log content
        host_data: Host data for context

    Returns:
        Findings with SSH command details
    """
    findings = []

    # Look for SSH command execution patterns
    # Common patterns in Nessus debug logs:
    # - "SSH: Executing command: <command>"
    # - "Running: <command>"
    # - "CMD: <command>"

    ssh_command_patterns = [
        r"SSH:\s+Executing command:\s+(.+)",
        r"Running:\s+(.+)",
        r"CMD:\s+(.+)",
        r"ssh_cmd_exec:\s+(.+)",
    ]

    commands_found = []
    for pattern in ssh_command_patterns:
        matches = re.finditer(pattern, debug_logs, re.MULTILINE | re.IGNORECASE)
        for match in matches:
            command = match.group(1).strip()
            if command and command not in commands_found:
                commands_found.append(command)

    if commands_found:
        evidence = [
            "SSH commands executed during scan:",
            "",
        ]
        evidence.extend([f"  • {cmd}" for cmd in commands_found[:20]])

        if len(commands_found) > 20:
            evidence.append(f"  ... and {len(commands_found) - 20} more commands")

        findings.append(
            Finding(
                category=FindingCategory.AUTHENTICATION,
                severity=Severity.INFO,
                title="SSH Command Execution Log Available",
                description=(
                    f"Debug logs captured {len(commands_found)} SSH commands executed during scanning. "
                    "These show exactly what Nessus tried to run on the target system."
                ),
                evidence=evidence,
                remediation=[
                    "Review the command list to ensure they executed successfully",
                    "Check for permission denied or command not found errors",
                    "Verify that all expected OS-specific commands were attempted",
                ],
                plugin_ids=[84239],
            )
        )

    return findings


def _parse_auth_attempts(debug_logs: str, host_data: HostData) -> list[Finding]:
    """Extract authentication attempt details.

    Args:
        debug_logs: Raw debug log content
        host_data: Host data for context

    Returns:
        Findings with authentication details
    """
    findings = []

    # Look for authentication-related patterns
    auth_patterns = [
        (r"Authentication failed:\s+(.+)", Severity.HIGH),
        (r"Login failed:\s+(.+)", Severity.HIGH),
        (r"Password authentication failed", Severity.HIGH),
        (r"Public key authentication failed", Severity.MEDIUM),
        (r"Permission denied", Severity.HIGH),
        (r"Authentication successful", Severity.INFO),
        (r"Login successful", Severity.INFO),
    ]

    auth_events = []
    for pattern, severity in auth_patterns:
        matches = re.finditer(pattern, debug_logs, re.MULTILINE | re.IGNORECASE)
        for match in matches:
            detail = match.group(0)
            auth_events.append((detail, severity))

    if auth_events:
        # Categorize by severity
        failures = [e for e in auth_events if e[1] in (Severity.HIGH, Severity.CRITICAL)]
        successes = [e for e in auth_events if e[1] == Severity.INFO]

        if failures:
            evidence = ["Authentication failures found in debug logs:", ""]
            evidence.extend([f"  • {e[0]}" for e in failures[:10]])

            if len(failures) > 10:
                evidence.append(f"  ... and {len(failures) - 10} more failures")

            findings.append(
                Finding(
                    category=FindingCategory.AUTHENTICATION,
                    severity=Severity.HIGH,
                    title="Authentication Failures Detected in Debug Logs",
                    description=(
                        f"Debug logs show {len(failures)} authentication failure(s). "
                        "These provide detailed error messages about why credentials failed."
                    ),
                    evidence=evidence,
                    remediation=[
                        "Review the exact error messages for root cause",
                        "Check if password is expired or account is locked",
                        "Verify SSH key permissions and format",
                        "Check for PAM or sshd_config restrictions",
                    ],
                    plugin_ids=[84239],
                )
            )

        if successes:
            evidence = ["Successful authentication events:", ""]
            evidence.extend([f"  • {e[0]}" for e in successes[:5]])

            findings.append(
                Finding(
                    category=FindingCategory.AUTHENTICATION,
                    severity=Severity.INFO,
                    title="Successful Authentication Confirmed",
                    description=(
                        f"Debug logs confirm {len(successes)} successful authentication event(s). "
                        "Initial authentication worked, but subsequent checks may have failed."
                    ),
                    evidence=evidence,
                    remediation=[
                        "If scan is still incomplete, issue is post-authentication",
                        "Check privilege escalation settings (sudo, etc.)",
                        "Verify file/directory permissions for security checks",
                    ],
                    plugin_ids=[84239],
                )
            )

    return findings


def _parse_plugin_errors(debug_logs: str, host_data: HostData) -> list[Finding]:
    """Extract plugin execution errors.

    Args:
        debug_logs: Raw debug log content
        host_data: Host data for context

    Returns:
        Findings with plugin error details
    """
    findings = []

    # Look for plugin errors
    error_patterns = [
        r"Plugin (\d+).*error:\s+(.+)",
        r"ERROR:\s+(.+)",
        r"FATAL:\s+(.+)",
        r"Failed to execute:\s+(.+)",
    ]

    errors_found = []
    for pattern in error_patterns:
        matches = re.finditer(pattern, debug_logs, re.MULTILINE | re.IGNORECASE)
        for match in matches:
            error_text = match.group(0)
            if error_text and error_text not in errors_found:
                errors_found.append(error_text)

    if errors_found:
        evidence = ["Plugin execution errors found:", ""]
        evidence.extend([f"  • {err}" for err in errors_found[:15]])

        if len(errors_found) > 15:
            evidence.append(f"  ... and {len(errors_found) - 15} more errors")

        findings.append(
            Finding(
                category=FindingCategory.POLICY,
                severity=Severity.MEDIUM,
                title="Plugin Execution Errors Detected",
                description=(
                    f"Debug logs show {len(errors_found)} plugin execution error(s). "
                    "These indicate specific checks that failed to run properly."
                ),
                evidence=evidence,
                remediation=[
                    "Review error messages for specific plugin failures",
                    "Check if required tools/commands are missing on target",
                    "Verify plugin feed version is up to date",
                    "Consider disabling problematic plugins if not critical",
                ],
                plugin_ids=[84239, 117530],
            )
        )

    return findings


def extract_ssh_command_summary(debug_logs: str) -> dict:
    """Extract a summary of SSH commands for LLM analysis.

    Args:
        debug_logs: Raw debug log content

    Returns:
        Dictionary with command summary statistics
    """
    ssh_command_patterns = [
        r"SSH:\s+Executing command:\s+(.+)",
        r"Running:\s+(.+)",
        r"CMD:\s+(.+)",
        r"ssh_cmd_exec:\s+(.+)",
    ]

    commands = []
    for pattern in ssh_command_patterns:
        matches = re.finditer(pattern, debug_logs, re.MULTILINE | re.IGNORECASE)
        for match in matches:
            command = match.group(1).strip()
            if command:
                commands.append(command)

    return {
        "total_commands": len(commands),
        "unique_commands": len(set(commands)),
        "sample_commands": commands[:10],
        "command_types": _categorize_commands(commands),
    }


def _categorize_commands(commands: list[str]) -> dict[str, int]:
    """Categorize commands by type.

    Args:
        commands: List of command strings

    Returns:
        Dictionary mapping category to count
    """
    categories = {
        "os_detection": 0,
        "package_management": 0,
        "file_inspection": 0,
        "network_config": 0,
        "service_status": 0,
        "other": 0,
    }

    for cmd in commands:
        cmd_lower = cmd.lower()

        if any(x in cmd_lower for x in ["uname", "cat /etc/", "lsb_release"]):
            categories["os_detection"] += 1
        elif any(x in cmd_lower for x in ["rpm", "dpkg", "yum", "apt", "pkg"]):
            categories["package_management"] += 1
        elif any(x in cmd_lower for x in ["cat", "grep", "ls", "find", "stat"]):
            categories["file_inspection"] += 1
        elif any(x in cmd_lower for x in ["ifconfig", "ip ", "netstat", "ss "]):
            categories["network_config"] += 1
        elif any(x in cmd_lower for x in ["systemctl", "service", "ps ", "pgrep"]):
            categories["service_status"] += 1
        else:
            categories["other"] += 1

    return categories
