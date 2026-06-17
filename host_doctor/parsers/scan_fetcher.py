"""Fetch and export scans from Tenable Vulnerability Management API.

This module handles:
- Looking up scans by name or ID
- Exporting scans to .nessus format
- Polling for export completion
- Downloading the exported file
"""

import logging
import time
from pathlib import Path
from tempfile import gettempdir
from typing import Optional, Union

from tenable.io import TenableIO

from host_doctor.config import config

logger = logging.getLogger(__name__)


class ScanFetcher:
    """Fetch and export scans from Tenable Vulnerability Management."""

    def __init__(self, tio: Optional[TenableIO] = None):
        """Initialize scan fetcher.

        Args:
            tio: Optional TenableIO instance. If not provided, will create one
                 from environment credentials.
        """
        self.tio = tio
        self._initialized = False

    def _ensure_initialized(self) -> bool:
        """Lazy initialization of Tenable API client.

        Returns:
            True if initialized successfully, False otherwise
        """
        if self._initialized:
            return True

        if self.tio is None:
            if not config.has_tenable_api_config():
                logger.error(
                    "Tenable API credentials not configured. "
                    "Set TIO_ACCESS_KEY and TIO_SECRET_KEY environment variables."
                )
                return False

            try:
                self.tio = TenableIO(
                    access_key=config.TIO_ACCESS_KEY,
                    secret_key=config.TIO_SECRET_KEY,
                )
                self._initialized = True
                return True
            except Exception as e:
                logger.error(f"Failed to initialize Tenable API client: {e}")
                return False

        self._initialized = True
        return True

    def find_scan_by_name(self, scan_name: str) -> Optional[dict]:
        """Find a scan by name (case-insensitive partial match).

        Args:
            scan_name: Name of the scan to find (supports partial match)

        Returns:
            Scan info dict with 'id', 'name', 'status', etc., or None if not found
        """
        if not self._ensure_initialized():
            return None

        try:
            logger.info(f"Searching for scan matching '{scan_name}'...")

            # List all scans
            scans = self.tio.scans.list()

            # Find matching scans (case-insensitive)
            matches = [
                s for s in scans
                if scan_name.lower() in s.get("name", "").lower()
            ]

            if not matches:
                logger.error(f"No scans found matching '{scan_name}'")
                return None

            if len(matches) > 1:
                logger.warning(
                    f"Found {len(matches)} scans matching '{scan_name}'. "
                    f"Using most recent: {matches[0].get('name')}"
                )
                # Sort by last_modification_date descending
                matches.sort(
                    key=lambda s: s.get("last_modification_date", 0),
                    reverse=True
                )

            scan = matches[0]
            logger.info(f"Found scan: {scan.get('name')} (ID: {scan.get('id')})")
            return scan

        except Exception as e:
            logger.error(f"Error searching for scan: {e}")
            return None

    def get_scan_details(self, scan_id: int) -> Optional[dict]:
        """Get detailed information about a scan.

        Args:
            scan_id: Scan ID

        Returns:
            Scan details dict, or None if error
        """
        if not self._ensure_initialized():
            return None

        try:
            details = self.tio.scans.details(scan_id)
            return details
        except Exception as e:
            logger.error(f"Error getting scan details for ID {scan_id}: {e}")
            return None

    def get_latest_completed_history_id(self, scan_id: int) -> Optional[int]:
        """Get the history_id of the most recent completed scan run.

        Args:
            scan_id: Scan ID

        Returns:
            History ID of the latest completed run, or None
        """
        if not self._ensure_initialized():
            return None

        try:
            # Use the history() iterator to get all history entries
            history_iter = self.tio.scans.history(scan_id)
            history = list(history_iter)

            if not history:
                logger.warning(f"No history found for scan {scan_id}")
                return None

            # Filter for completed runs
            completed_runs = [
                h for h in history
                if h.get("status") == "completed"
            ]

            if not completed_runs:
                logger.warning(f"No completed runs found for scan {scan_id}")
                return None

            # Sort by time_end descending to get most recent
            completed_runs.sort(
                key=lambda h: h.get("time_end", 0),
                reverse=True
            )

            latest = completed_runs[0]
            # The field is 'id', not 'history_id' in the new API
            history_id = latest.get("id")

            logger.info(
                f"Using latest completed run: history_id={history_id} "
                f"(status={latest.get('status')}, scan_uuid={latest.get('scan_uuid')})"
            )
            return history_id

        except Exception as e:
            logger.error(f"Error getting history for scan {scan_id}: {e}")
            return None

    def export_scan(
        self,
        scan_id: int,
        history_id: Optional[int] = None,
        output_path: Optional[Path] = None,
        timeout: int = 300,
    ) -> Optional[Path]:
        """Export a scan to .nessus format and download it.

        Args:
            scan_id: Scan ID to export
            history_id: Optional specific scan run. If None, uses latest completed.
            output_path: Where to save the file. If None, saves to temp directory.
            timeout: Max seconds to wait for export (default: 300)

        Returns:
            Path to downloaded .nessus file, or None if failed
        """
        if not self._ensure_initialized():
            return None

        try:
            # If no history_id provided, get the latest completed one
            if history_id is None:
                history_id = self.get_latest_completed_history_id(scan_id)
                if history_id is None:
                    logger.error(f"Cannot export scan {scan_id}: no completed runs")
                    return None

            logger.info(f"Exporting scan {scan_id}, history_id={history_id}...")

            # Determine output path
            if output_path is None:
                # Generate temp path
                scan_details = self.get_scan_details(scan_id)
                scan_name = scan_details.get("settings", {}).get("name", f"scan_{scan_id}")
                # Sanitize filename
                safe_name = "".join(
                    c if c.isalnum() or c in ("-", "_") else "_"
                    for c in scan_name
                )
                output_path = Path(gettempdir()) / f"{safe_name}.nessus"

            logger.info(f"Downloading to {output_path}...")

            # Export directly to file
            # The pyTenable export() method handles polling internally
            with open(output_path, "wb") as f:
                self.tio.scans.export(
                    scan_id=scan_id,
                    history_id=history_id,
                    format="nessus",
                    fobj=f
                )

            logger.info(f"✓ Successfully downloaded {output_path.stat().st_size} bytes")
            return output_path

        except Exception as e:
            logger.error(f"Error exporting scan: {e}")
            return None

    def fetch_scan(
        self,
        scan_identifier: Union[int, str],
        history_id: Optional[int] = None,
        output_path: Optional[Path] = None,
    ) -> Optional[Path]:
        """High-level method: find and export a scan by ID or name.

        Args:
            scan_identifier: Scan ID (int) or scan name (str)
            history_id: Optional specific scan run
            output_path: Where to save the file

        Returns:
            Path to downloaded .nessus file, or None if failed
        """
        if not self._ensure_initialized():
            return None

        # Handle scan lookup by name vs ID
        if isinstance(scan_identifier, str):
            scan = self.find_scan_by_name(scan_identifier)
            if not scan:
                return None
            scan_id = scan.get("id")
        else:
            scan_id = scan_identifier

        # Export and download
        return self.export_scan(
            scan_id=scan_id,
            history_id=history_id,
            output_path=output_path
        )
