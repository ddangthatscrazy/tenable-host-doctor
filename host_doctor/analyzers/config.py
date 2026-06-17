"""Extract scan configuration from parsed data."""

from host_doctor.models import ScanConfig


def extract_scan_config(scan_data: dict) -> ScanConfig:
    """Extract scan configuration from parsed scan data.

    This is now handled by the parser itself, but keeping this
    function for compatibility.

    Args:
        scan_data: Parsed scan data from parse_nessus_file()

    Returns:
        ScanConfig object
    """
    return scan_data["scan_config"]
