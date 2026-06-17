"""Cross-plugin correlation utilities.

Detects authentication success/failure by checking MULTIPLE plugins,
not just the primary indicators. This reduces false negatives.
"""

from host_doctor.models import HostData


# Plugin IDs that indicate successful authentication
WINDOWS_AUTH_SUCCESS_PLUGINS = {
    102094: "Microsoft Windows SMB Login Successful",
    10394: "Microsoft Windows SMB Log In Possible",
    10396: "Microsoft Windows SMB Shares Access",
    26917: "Microsoft Windows SMB Registry : Microsoft Windows SMB Registry Access",
    20811: "Microsoft Windows Installed Software Enumeration (credentialed check)",
}

SSH_AUTH_SUCCESS_PLUGINS = {
    141118: "Target Credential Status by Authentication Protocol - Valid Credentials Provided",
    12634: "SSH Protocol Versions Supported",
    56300: "KVM / QEMU Guest Detection (credentialed check)",
}

VMWARE_AUTH_SUCCESS_PLUGINS = {
    20094: "VMware ESXi Detection",
    89105: "VMware ESXi Patch Level",
    66809: "VMware vCenter Detection",
}

# Plugin families that require successful authentication
LINUX_PATCH_FAMILIES = [
    "Red Hat Local Security Checks",
    "Debian Local Security Checks",
    "Ubuntu Local Security Checks",
    "CentOS Local Security Checks",
    "Oracle Linux Local Security Checks",
]

WINDOWS_PATCH_FAMILIES = [
    "Windows : Microsoft Bulletins",
    "Windows : User management",
]


def check_windows_auth_success(host_data: HostData) -> dict:
    """Check multiple plugins to determine if Windows authentication succeeded.

    Returns dict with:
        - success: bool
        - evidence: list of plugin IDs that prove auth worked
        - confidence: str ("high", "medium", "low")
    """
    evidence = []

    # Check all known Windows auth indicators
    for plugin_id, plugin_name in WINDOWS_AUTH_SUCCESS_PLUGINS.items():
        if host_data.has_plugin(plugin_id):
            evidence.append((plugin_id, plugin_name))

    # Check for Windows patch data (strongest indicator)
    has_patch_data = any(
        len(host_data.get_vulnerabilities_by_family(family)) > 0
        for family in WINDOWS_PATCH_FAMILIES
    )

    if has_patch_data:
        evidence.append((0, "Windows patch data present"))

    # Determine confidence
    success = len(evidence) > 0

    if has_patch_data and len(evidence) > 2:
        confidence = "high"
    elif has_patch_data or len(evidence) >= 2:
        confidence = "medium"
    elif len(evidence) == 1:
        confidence = "low"
    else:
        confidence = "none"

    return {
        "success": success,
        "evidence": evidence,
        "confidence": confidence,
        "has_patch_data": has_patch_data,
    }


def check_ssh_auth_success(host_data: HostData) -> dict:
    """Check multiple plugins to determine if SSH authentication succeeded.

    Returns dict with:
        - success: bool
        - evidence: list of plugin IDs that prove auth worked
        - confidence: str ("high", "medium", "low")
    """
    evidence = []

    # Check all known SSH auth indicators
    for plugin_id, plugin_name in SSH_AUTH_SUCCESS_PLUGINS.items():
        if host_data.has_plugin(plugin_id):
            evidence.append((plugin_id, plugin_name))

    # Check for Linux patch data (strongest indicator)
    has_patch_data = any(
        len(host_data.get_vulnerabilities_by_family(family)) > 0
        for family in LINUX_PATCH_FAMILIES
    )

    if has_patch_data:
        evidence.append((0, "Linux patch data present"))

    # Determine confidence
    success = len(evidence) > 0

    if has_patch_data and len(evidence) > 2:
        confidence = "high"
    elif has_patch_data or len(evidence) >= 2:
        confidence = "medium"
    elif len(evidence) == 1:
        confidence = "low"
    else:
        confidence = "none"

    return {
        "success": success,
        "evidence": evidence,
        "confidence": confidence,
        "has_patch_data": has_patch_data,
    }


def check_vmware_auth_success(host_data: HostData) -> dict:
    """Check for VMware/ESXi authentication success.

    Returns dict with:
        - success: bool
        - evidence: list of plugin IDs
        - confidence: str
    """
    evidence = []

    for plugin_id, plugin_name in VMWARE_AUTH_SUCCESS_PLUGINS.items():
        if host_data.has_plugin(plugin_id):
            evidence.append((plugin_id, plugin_name))

    success = len(evidence) > 0
    confidence = "high" if len(evidence) >= 2 else "medium" if len(evidence) == 1 else "none"

    return {
        "success": success,
        "evidence": evidence,
        "confidence": confidence,
    }


def check_any_auth_success(host_data: HostData) -> dict:
    """Check all authentication methods and return aggregated results.

    Returns dict with:
        - windows: dict from check_windows_auth_success
        - ssh: dict from check_ssh_auth_success
        - vmware: dict from check_vmware_auth_success
        - any_success: bool (True if ANY protocol authenticated)
    """
    windows = check_windows_auth_success(host_data)
    ssh = check_ssh_auth_success(host_data)
    vmware = check_vmware_auth_success(host_data)

    any_success = windows["success"] or ssh["success"] or vmware["success"]

    return {
        "windows": windows,
        "ssh": ssh,
        "vmware": vmware,
        "any_success": any_success,
    }
