"""Helper functions for extracting evidence from plugin outputs."""

import re
from typing import Optional

from host_doctor.models import HostData


def extract_ssh_user_from_output(output: str) -> str:
    """Extract SSH username from plugin 104410 output.

    Example output:
        - User : root

    Args:
        output: Plugin output text

    Returns:
        Username or "unknown" if not found
    """
    match = re.search(r'-\s*User\s*:\s*(\S+)', output, re.MULTILINE | re.IGNORECASE)
    return match.group(1) if match else "unknown"


def extract_error_count(output: str) -> str:
    """Extract error count from plugin 117885 output.

    Example output:
        2 Initial SMB negotiation : smb_negotiate_protocol() failed.

    Args:
        output: Plugin output text

    Returns:
        Error description or "unknown count" if not found
    """
    match = re.search(r'(\d+)\s+([^:]+):', output, re.MULTILINE)
    return match.group(0).strip() if match else "unknown count"


def count_os_specific_plugins(host_data: HostData) -> int:
    """Count OS-specific local security check plugins.

    These families indicate successful authenticated scanning:
    - CentOS Local Security Checks
    - Red Hat Local Security Checks
    - Ubuntu Local Security Checks
    - Oracle Linux Local Security Checks
    - Amazon Linux Local Security Checks
    - Debian Local Security Checks
    - SuSE Local Security Checks
    - Fedora Local Security Checks

    Args:
        host_data: Host scan results

    Returns:
        Count of OS-specific plugin family items
    """
    os_families = [
        "CentOS Local Security Checks",
        "Red Hat Local Security Checks",
        "Ubuntu Local Security Checks",
        "Oracle Linux Local Security Checks",
        "Amazon Linux Local Security Checks",
        "Debian Local Security Checks",
        "SuSE Local Security Checks",
        "Fedora Local Security Checks",
    ]
    count = 0
    for vuln in host_data.vulnerabilities:
        if vuln.family in os_families:
            count += 1
    return count


def count_windows_family_plugins(host_data: HostData) -> int:
    """Count Windows plugin family items.

    Args:
        host_data: Host scan results

    Returns:
        Count of Windows family plugins
    """
    count = 0
    for vuln in host_data.vulnerabilities:
        if vuln.family.startswith("Windows"):
            count += 1
    return count


def has_bulletin_plugins(host_data: HostData) -> bool:
    """Check if Windows Bulletin plugins are present.

    Args:
        host_data: Host scan results

    Returns:
        True if any bulletin family plugins found
    """
    for vuln in host_data.vulnerabilities:
        if "Bulletins" in vuln.family or "Microsoft Bulletins" in vuln.family:
            return True
    return False


def extract_open_ports(host_data: HostData) -> list[int]:
    """Extract list of open ports from vulnerabilities.

    Args:
        host_data: Host scan results

    Returns:
        Sorted list of unique port numbers
    """
    ports = set()
    for vuln in host_data.vulnerabilities:
        if vuln.port and vuln.port > 0:
            ports.add(vuln.port)
    return sorted(ports)


def get_plugin_families_present(host_data: HostData) -> set[str]:
    """Get set of all plugin families that have results.

    Args:
        host_data: Host scan results

    Returns:
        Set of family names
    """
    families = set()
    for vuln in host_data.vulnerabilities:
        families.add(vuln.family)
    return families


def has_ssh_indicators(host_data: HostData) -> bool:
    """Check if host has SSH-related indicators.

    Looks for:
    - Port 22 open
    - SSH-related plugin outputs
    - Linux OS detection

    Args:
        host_data: Host scan results

    Returns:
        True if SSH indicators present
    """
    # Check for port 22
    open_ports = extract_open_ports(host_data)
    if 22 in open_ports:
        return True

    # Check for Linux OS
    if host_data.operating_system:
        os_lower = host_data.operating_system.lower()
        if any(keyword in os_lower for keyword in ["linux", "unix", "centos", "ubuntu", "redhat"]):
            return True

    return False


def has_smb_indicators(host_data: HostData) -> bool:
    """Check if host has SMB-related indicators.

    Looks for:
    - Port 445 or 139 open
    - Windows OS detection

    Args:
        host_data: Host scan results

    Returns:
        True if SMB indicators present
    """
    # Check for SMB ports
    open_ports = extract_open_ports(host_data)
    if 445 in open_ports or 139 in open_ports:
        return True

    # Check for Windows OS
    if host_data.operating_system:
        os_lower = host_data.operating_system.lower()
        if "windows" in os_lower:
            return True

    return False


def extract_credential_info(output: str) -> dict[str, Optional[str]]:
    """Extract credential information from plugin outputs.

    Extracts:
    - Protocol (SSH, SMB, etc.)
    - Port number
    - Username
    - Domain (if applicable)

    Args:
        output: Plugin output text

    Returns:
        Dictionary with extracted info
    """
    info = {
        "protocol": None,
        "port": None,
        "user": None,
        "domain": None,
    }

    # Extract protocol
    protocol_match = re.search(r'Protocol\s*:\s*(\S+)', output, re.IGNORECASE)
    if protocol_match:
        info["protocol"] = protocol_match.group(1)

    # Extract port
    port_match = re.search(r'Port\s*:\s*(\d+)', output, re.IGNORECASE)
    if port_match:
        info["port"] = port_match.group(1)

    # Extract user (various formats)
    user_match = re.search(r'(?:User|Username)\s*:\s*(\S+)', output, re.IGNORECASE)
    if user_match:
        user = user_match.group(1)
        # Check if domain\user format
        if '\\' in user:
            parts = user.split('\\', 1)
            info["domain"] = parts[0]
            info["user"] = parts[1]
        else:
            info["user"] = user

    return info


def get_plugin_output_excerpt(output: Optional[str], max_length: int = 200) -> str:
    """Get a truncated excerpt of plugin output for display.

    Args:
        output: Full plugin output
        max_length: Maximum length of excerpt

    Returns:
        Truncated output with ellipsis if needed
    """
    if not output:
        return "No output available"

    # Clean up whitespace
    output = output.strip()

    if len(output) <= max_length:
        return output

    return output[:max_length] + "..."
