"""Nessus .nessus XML file parser.

Parses Tenable .nessus export files and converts to HostData/ScanConfig objects.
"""

import xml.etree.ElementTree as ET
from datetime import datetime
from pathlib import Path
from typing import Optional

from host_doctor.models import (
    HostData,
    Plugin,
    ScanConfig,
    Vulnerability,
)


# Diagnostic plugins we always want to extract.
# Labels verified against the Tenable plugin database (developer.tenable.com /
# tenable.com/plugins). Several previous labels were wrong and drove incorrect
# diagnoses; see credential_state.py for how these are used.
DIAGNOSTIC_PLUGINS = {
    19506: "Nessus Scan Information",
    84239: "Authentication Failure - Debugging Log",
    112154: "Enumerate Launched Plugins",
    91822: "Database Authentication Failure",
    122503: "Integration Credential Status - Failure",
    # --- Target Credential Status by Authentication Protocol (per-protocol auth) ---
    104410: "Target Credential Status by Authentication Protocol - Failure for Provided Credentials",
    110723: "Target Credential Status by Authentication Protocol - No Credentials Provided",
    141118: "Target Credential Status by Authentication Protocol - Valid Credentials Provided",
    # --- Target Credential Issues by Authentication Protocol (post-auth quality) ---
    110095: "Target Credential Issues by Authentication Protocol - No Issues Found",
    110385: "Target Credential Issues by Authentication Protocol - Insufficient Privilege",
    117885: "Target Credential Issues by Authentication Protocol - Intermittent Authentication Failure",
    # --- OS Security Patch Assessment (did local checks actually run?) ---
    117887: "OS Security Patch Assessment Available",          # authoritative success
    117886: "OS Security Patch Assessment Not Available",       # informational, not a failure
    110695: "OS Security Patch Assessment Checks Not Supported",  # OS unsupported for local checks
    21745: "Authentication Failure - Local Checks Not Run",     # umbrella: auth is only ONE cause
    # --- Privilege / registry (Windows + SSH escalation) ---
    102094: "SSH Commands Require Privilege Escalation",        # was mislabeled as SMB login success
    24786: "Nessus Windows Scan Not Performed with Admin Privileges",
    26917: "Microsoft Windows SMB Registry: Nessus Cannot Access the Windows Registry",
    35705: "SMB Registry: Starting the Registry Service during the scan failed",
    35706: "SMB Registry: Stopping the Registry Service after the scan failed",
    122501: "SSH Rate Limited Device",
    # --- Diagnostics / connectivity ---
    117530: "Errors in nessusd.dump",
    10114: "ICMP Timestamp Request Remote Date Disclosure",
    10180: "Ping the remote host",
}


def _merge_plugins(existing: "Plugin", new: "Plugin") -> "Plugin":
    """Combine two Plugin records for the same plugin_id.

    Concatenates distinct, non-empty outputs (preserving order, dropping exact
    duplicates) so evidence emitted on multiple ports/protocols is not lost.
    """
    parts: list[str] = []
    for body in (existing.plugin_output, new.plugin_output):
        if body and body not in parts:
            parts.append(body)
    merged_output = "\n\n".join(parts) if parts else (existing.plugin_output or new.plugin_output)
    # Prefer the record that actually carried output for name/family metadata.
    base = existing if existing.plugin_output else new
    return Plugin(
        plugin_id=base.plugin_id,
        plugin_name=base.plugin_name,
        family=base.family,
        severity=max(existing.severity, new.severity),
        plugin_output=merged_output,
    )


def parse_nessus_file(file_path: Path) -> dict[str, any]:
    """Parse a .nessus file and return structured scan data.

    Args:
        file_path: Path to .nessus XML file

    Returns:
        dict with:
            - hosts: list[HostData]
            - scan_config: ScanConfig
            - scan_name: str
            - policy_name: str

    Raises:
        FileNotFoundError: If file doesn't exist
        ValueError: If file is not valid .nessus XML
    """
    if not file_path.exists():
        raise FileNotFoundError(f".nessus file not found: {file_path}")

    # Validate file
    valid, msg = validate_nessus_file(file_path)
    if not valid:
        raise ValueError(msg)

    # Parse XML
    try:
        tree = ET.parse(file_path)
        root = tree.getroot()
    except ET.ParseError as e:
        raise ValueError(f"Invalid XML in .nessus file: {e}")

    if root.tag != "NessusClientData_v2":
        raise ValueError(f"Not a valid .nessus file (root tag: {root.tag})")

    report = root.find("Report")
    if report is None:
        raise ValueError("No Report element found in .nessus file")

    # Extract scan metadata
    scan_name = report.get("name", "Unknown Scan")
    policy_name = _extract_policy_name(root)
    targets = _extract_targets(root)

    # Parse all hosts
    # Note: .nessus files can have multiple ReportHost entries for the same IP
    # This happens when Tenable exports plugin results in batches/segments
    # We need to MERGE all entries for the same IP to get complete data
    hosts_by_ip = {}
    scan_start = None
    scan_end = None

    for host_elem in report.findall("ReportHost"):
        host_data = _parse_host(host_elem)

        # If we've seen this IP before, merge the plugin data
        if host_data.host_ip in hosts_by_ip:
            existing = hosts_by_ip[host_data.host_ip]

            # Merge plugins. On a repeat plugin_id, combine outputs so evidence
            # from a second host record isn't silently dropped.
            for plugin_id, plugin in host_data.plugins.items():
                if plugin_id in existing.plugins:
                    existing.plugins[plugin_id] = _merge_plugins(
                        existing.plugins[plugin_id], plugin
                    )
                else:
                    existing.plugins[plugin_id] = plugin

            # Merge vulnerabilities (add any new ones)
            for vuln in host_data.vulnerabilities:
                # Check if this vulnerability is already in the list
                # (same plugin_id, port, protocol)
                is_duplicate = False
                for existing_vuln in existing.vulnerabilities:
                    if (existing_vuln.plugin_id == vuln.plugin_id and
                        existing_vuln.port == vuln.port and
                        existing_vuln.protocol == vuln.protocol):
                        is_duplicate = True
                        break

                if not is_duplicate:
                    existing.vulnerabilities.append(vuln)

            # Keep the most complete host metadata
            # Prefer non-None values
            if not existing.operating_system and host_data.operating_system:
                existing.operating_system = host_data.operating_system
            if not existing.hostname and host_data.hostname:
                existing.hostname = host_data.hostname
            if not existing.netbios_name and host_data.netbios_name:
                existing.netbios_name = host_data.netbios_name

            # Keep earliest start and latest end times
            if host_data.host_start and (not existing.host_start or host_data.host_start < existing.host_start):
                existing.host_start = host_data.host_start
            if host_data.host_end and (not existing.host_end or host_data.host_end > existing.host_end):
                existing.host_end = host_data.host_end

            # Recalculate scan duration
            if existing.host_start and existing.host_end:
                existing.scan_duration_seconds = (existing.host_end - existing.host_start).total_seconds()
        else:
            hosts_by_ip[host_data.host_ip] = host_data

        # Track earliest start and latest end
        if host_data.host_start:
            if not scan_start or host_data.host_start < scan_start:
                scan_start = host_data.host_start
        if host_data.host_end:
            if not scan_end or host_data.host_end > scan_end:
                scan_end = host_data.host_end

    # Convert dict back to list
    hosts = list(hosts_by_ip.values())

    # Extract scan configuration from plugin 19506 (if present)
    scan_config = _extract_scan_config(hosts, scan_name, policy_name, scan_start, scan_end)

    return {
        "hosts": hosts,
        "scan_config": scan_config,
        "scan_name": scan_name,
        "policy_name": policy_name,
        "targets": targets,
    }


def _extract_policy_name(root: ET.Element) -> str:
    """Extract policy name from XML."""
    policy = root.find(".//Policy/policyName")
    return policy.text if policy is not None and policy.text else "Unknown"


def _extract_targets(root: ET.Element) -> list[str]:
    """Extract target list from scan preferences."""
    for pref in root.findall(".//preference"):
        name = pref.find("name")
        value = pref.find("value")
        if name is not None and name.text == "TARGET":
            if value is not None and value.text:
                return [t.strip() for t in value.text.split(",")]
    return []


def _parse_host(host_elem: ET.Element) -> HostData:
    """Parse a single ReportHost element into HostData."""
    hostname = host_elem.get("name", "unknown")

    # Parse host properties
    properties = {}
    host_props = host_elem.find("HostProperties")
    if host_props is not None:
        for tag in host_props.findall("tag"):
            name = tag.get("name")
            if name and tag.text:
                properties[name] = tag.text

    # Extract key properties
    host_ip = properties.get("host-ip", hostname)
    operating_system = properties.get("operating-system")
    mac_address = properties.get("mac-address")
    netbios_name = properties.get("netbios-name")

    # Parse timing
    host_start = _parse_timestamp(properties.get("HOST_START"))
    host_end = _parse_timestamp(properties.get("HOST_END"))
    scan_duration_seconds = None
    if host_start and host_end:
        scan_duration_seconds = (host_end - host_start).total_seconds()

    # Parse all plugins/vulnerabilities
    plugins = {}
    vulnerabilities = []

    for item in host_elem.findall("ReportItem"):
        plugin_id = int(item.get("pluginID", 0))
        plugin_name = item.get("pluginName", "Unknown")
        plugin_family = item.get("pluginFamily", "Unknown")
        severity = int(item.get("severity", 0))
        port = item.get("port")
        protocol = item.get("protocol")

        # Extract plugin output
        output_elem = item.find("plugin_output")
        plugin_output = output_elem.text.strip() if output_elem is not None and output_elem.text else None

        # Store plugin data (especially for diagnostic plugins).
        # Nessus can emit the same plugin_id on multiple ports/protocols; for
        # diagnostic/auth plugins, losing a body can flip protocol detection or
        # root-cause classification. So on a repeat ID we MERGE outputs rather than
        # overwrite (keeping the last would silently drop decisive evidence).
        if plugin_id in DIAGNOSTIC_PLUGINS or plugin_output:
            new_plugin = Plugin(
                plugin_id=plugin_id,
                plugin_name=plugin_name,
                family=plugin_family,
                severity=severity,
                plugin_output=plugin_output,
            )
            if plugin_id in plugins:
                plugins[plugin_id] = _merge_plugins(plugins[plugin_id], new_plugin)
            else:
                plugins[plugin_id] = new_plugin

        # Add to vulnerabilities list (for query purposes)
        vulnerabilities.append(
            Vulnerability(
                plugin_id=plugin_id,
                plugin_name=plugin_name,
                family=plugin_family,
                severity=severity,
                port=int(port) if port and port.isdigit() else None,
                protocol=protocol,
                plugin_output=plugin_output,
            )
        )

    # Check if host was reachable
    is_reachable = len(vulnerabilities) > 0

    # Check if scan completed normally (no timeout indicators)
    scan_completed = not any(
        v.plugin_name and "timeout" in v.plugin_name.lower() for v in vulnerabilities
    )

    return HostData(
        host_ip=host_ip,
        hostname=hostname if hostname != host_ip else None,
        operating_system=operating_system,
        mac_address=mac_address,
        netbios_name=netbios_name,
        host_start=host_start,
        host_end=host_end,
        scan_duration_seconds=scan_duration_seconds,
        vulnerabilities=vulnerabilities,
        plugins=plugins,
        is_reachable=is_reachable,
        scan_completed=scan_completed,
    )


def _parse_timestamp(timestamp_str: Optional[str]) -> Optional[datetime]:
    """Parse timestamp from HOST_START/HOST_END property.

    Format examples:
    - "Mon Jun 16 14:30:45 2026"
    - Unix timestamp as string
    """
    if not timestamp_str:
        return None

    try:
        # Try parsing as Unix timestamp
        if timestamp_str.isdigit():
            return datetime.fromtimestamp(int(timestamp_str))

        # The "%a %b %d %H:%M:%S %Y" format uses locale-dependent day/month
        # abbreviations, which breaks on non-English systems. Force C locale
        # for parsing, then restore the original.
        import locale

        formats = [
            "%a %b %d %H:%M:%S %Y",  # Mon Jun 16 14:30:45 2026
            "%Y-%m-%d %H:%M:%S",      # 2026-06-16 14:30:45
            "%Y/%m/%d %H:%M:%S",      # 2026/06/16 14:30:45
        ]

        saved = locale.getlocale(locale.LC_TIME)
        try:
            locale.setlocale(locale.LC_TIME, "C")
            for fmt in formats:
                try:
                    return datetime.strptime(timestamp_str, fmt)
                except ValueError:
                    continue
        finally:
            try:
                locale.setlocale(locale.LC_TIME, saved)
            except locale.Error:
                pass  # If restoring fails, leave as C — better than crashing

    except Exception:
        pass

    return None


def _extract_scan_config(
    hosts: list[HostData],
    scan_name: str,
    policy_name: str,
    scan_start: Optional[datetime],
    scan_end: Optional[datetime],
) -> ScanConfig:
    """Extract scan configuration, primarily from plugin 19506 output."""

    scan_config = ScanConfig(
        scan_name=scan_name,
        policy_name=policy_name,
        scan_start=scan_start,
        scan_end=scan_end,
    )

    # Find plugin 19506 in any host (config is same for all hosts)
    plugin_19506_output = None
    for host in hosts:
        if host.has_plugin(19506):
            plugin_19506_output = host.get_plugin_output(19506)
            break

    if plugin_19506_output:
        scan_config.scan_config_output = plugin_19506_output
        _parse_plugin_19506(plugin_19506_output, scan_config)

    # Fallback credential detection: only used when plugin 19506 didn't supply
    # credential info (e.g. plugin disabled or parsing failed). Uses both success
    # AND failure plugins so auth failures still signal "creds were configured".
    # Guarded by the condition to avoid overriding correct 19506-parsed values.
    if not scan_config.has_ssh_creds and not scan_config.has_windows_creds:
        for host in hosts:
            if host.has_plugin(141118) or host.has_plugin(104410):  # SSH success or failure
                scan_config.has_ssh_creds = True
            if host.has_plugin(102094) or host.has_plugin(21745):  # Windows success or failure
                scan_config.has_windows_creds = True
        # SNMP detection would be similar

    # Collect plugin families from all hosts
    families = set()
    for host in hosts:
        for vuln in host.vulnerabilities:
            families.add(vuln.family)

    scan_config.enabled_plugin_families = sorted(list(families))

    return scan_config


def _parse_plugin_19506(output: str, scan_config: ScanConfig) -> None:
    """Parse plugin 19506 output to extract scan configuration details.

    Enhanced to extract ALL configuration data including:
    - Credential information (what cred was used, protocol)
    - Network metrics (ping RTT, timeouts)
    - Scanner settings (debugging, paranoia, thorough tests)
    - Port scanner type and coverage
    """

    for line in output.split("\n"):
        line = line.strip()
        if not line or ":" not in line:
            continue

        # Split on first colon
        parts = line.split(":", 1)
        if len(parts) != 2:
            continue

        key = parts[0].strip().lower()
        value = parts[1].strip()

        # Basic scan metadata
        if "nessus version" in key:
            scan_config.nessus_version = value
        elif "plugin feed" in key or "plugin set" in key:
            scan_config.plugin_feed_version = value
        elif "scan name" in key:
            if not scan_config.scan_name:  # Don't override if already set
                scan_config.scan_name = value
        elif "scan policy" in key:
            if not scan_config.policy_name:
                scan_config.policy_name = value

        # Sensor type. Primary signal: the "Scan type" field contains "Agent"
        # (e.g. "Windows Agent") for agent scans. NOTE: "Scanner edition used"
        # is NOT reliable — it can read "Nessus Scanner" even for agent scans.
        elif key == "scan type" or key.endswith("scan type"):
            scan_config.sensor_type = "agent" if "agent" in value.lower() else "scanner"
        # Fallback: agents run on the host itself, so a loopback scanner IP
        # corroborates an agent scan when "Scan type" was absent/ambiguous.
        elif "scanner ip" in key:
            if scan_config.sensor_type is None and value.strip() in ("127.0.0.1", "::1"):
                scan_config.sensor_type = "agent"

        # Security settings
        elif "safe checks" in key:
            scan_config.safe_checks_enabled = "yes" in value.lower() or "on" in value.lower()
        elif "thorough tests" in key:
            scan_config.thorough_tests = "yes" in value.lower()
        elif "experimental tests" in key:
            scan_config.experimental_tests = "yes" in value.lower()
        elif "paranoia level" in key:
            try:
                scan_config.paranoia_level = int(value)
            except ValueError:
                pass

        # Network settings
        elif "port range" in key:
            scan_config.port_range = value
        elif "max checks" in key or "max simultaneous" in key:
            try:
                scan_config.max_checks_per_host = int(value.split()[0])
            except (ValueError, IndexError):
                pass
        elif "recv timeout" in key or "network timeout" in key:
            try:
                timeout_str = value.split()[0]
                scan_config.network_timeout = int(timeout_str)
            except (ValueError, IndexError):
                pass
        elif "ping rtt" in key:
            # Extract RTT in milliseconds
            try:
                rtt_str = value.split()[0]
                scan_config.ping_rtt_ms = float(rtt_str)
            except (ValueError, IndexError):
                pass

        # Port scanner type
        elif "port scanner" in key:
            scan_config.port_scanner_type = value

        # Credential information (CRITICAL for diagnostics)
        elif "credentialed checks" in key:
            # Format: "yes, as 'domain\user' via SMB"
            # or: "yes" or "no"
            if "yes" in value.lower():
                scan_config.has_windows_creds = "smb" in value.lower() or "wmi" in value.lower()
                scan_config.has_ssh_creds = "ssh" in value.lower()

                # Extract the actual username if present
                # Format: "yes, as 'user' via protocol"
                if "as" in value.lower() and "via" in value.lower():
                    try:
                        # Extract credential string between quotes or spaces
                        cred_part = value.split("as")[1].split("via")[0].strip().strip("'\"")
                        protocol_part = value.split("via")[1].strip().split()[0]
                        scan_config.credential_used = cred_part
                        scan_config.credential_protocol = protocol_part
                    except (IndexError, ValueError):
                        pass

        # Debugging settings
        elif "plugin debugging" in key:
            # Format: "yes (at debugging level 3)" or "no"
            if "yes" in value.lower():
                scan_config.debugging_enabled = True
                # Extract level if present
                if "level" in value.lower():
                    try:
                        level_str = value.split("level")[1].strip().rstrip(")")
                        scan_config.debugging_level = int(level_str)
                    except (ValueError, IndexError):
                        pass
            else:
                scan_config.debugging_enabled = False

        # Scan optimization settings
        elif "optimize the test" in key:
            scan_config.optimize_tests = "yes" in value.lower()
        elif "report verbosity" in key:
            try:
                scan_config.report_verbosity = int(value)
            except ValueError:
                pass


def validate_nessus_file(file_path: Path) -> tuple[bool, str]:
    """Validate if file is a parseable .nessus file.

    Args:
        file_path: Path to .nessus file

    Returns:
        (is_valid, message) tuple
    """
    if not file_path.exists():
        return False, f"File not found: {file_path}"

    if file_path.suffix.lower() != ".nessus":
        return False, f"Not a .nessus file (extension: {file_path.suffix})"

    # Check file size
    size_mb = file_path.stat().st_size / (1024 * 1024)
    if size_mb > 500:  # Allow larger files than scan-doctor
        return False, f"File too large ({size_mb:.1f} MB, max 500 MB)"

    # Check file content
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            first_line = f.readline()
            if "NessusClientData" not in first_line and "<?xml" not in first_line:
                return False, "Not a valid .nessus XML file"
    except Exception as e:
        return False, f"Cannot read file: {e}"

    return True, "Valid .nessus file"
