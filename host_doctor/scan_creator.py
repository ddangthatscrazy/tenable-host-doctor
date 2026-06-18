"""Scan management — enable debugging, launch targeted scans, poll for completion."""

import logging
import time
from typing import Any, Optional

from host_doctor.models import ScanConfig

logger = logging.getLogger(__name__)

# Statuses where we keep polling
_RUNNING_STATUSES = {"running", "pending", "resuming", "processing"}
# Statuses that mean the scan finished successfully
_DONE_STATUSES = {"completed", "imported"}
# Statuses that mean something went wrong
_FAILED_STATUSES = {"aborted", "empty", "canceled"}


class ScanManager:
    """Manage Tenable scan configuration and execution via the API.

    Used by the debug loop to enable plugin debugging on an existing scan,
    launch it against a single host, and wait for it to finish.

    Requires pytenable (pip install -e ".[api]") and TIO_ACCESS_KEY /
    TIO_SECRET_KEY environment variables (or explicit credentials at init time).
    """

    def __init__(self, tio=None):
        """Initialize ScanManager.

        Args:
            tio: Optional TenableIO instance. If not provided, one is created
                 lazily from environment credentials on first use.
        """
        self._tio = tio
        self._initialized = False

    def _ensure_initialized(self) -> bool:
        """Lazy-initialize the Tenable API client.

        Returns:
            True if ready, False if credentials are missing or pytenable is not installed.
        """
        if self._initialized:
            return True

        if self._tio is not None:
            self._initialized = True
            return True

        try:
            from tenable.io import TenableIO
        except ImportError:
            logger.error(
                "pytenable is not installed. "
                "Run: pip install -e '.[api]'"
            )
            return False

        from host_doctor.config import config

        if not config.has_tenable_api_config():
            logger.error(
                "Tenable API credentials not configured. "
                "Set TIO_ACCESS_KEY and TIO_SECRET_KEY environment variables."
            )
            return False

        try:
            self._tio = TenableIO(
                access_key=config.TIO_ACCESS_KEY,
                secret_key=config.TIO_SECRET_KEY,
            )
            self._initialized = True
            return True
        except Exception as e:
            logger.error(f"Failed to initialize Tenable API client: {e}")
            return False

    def enable_debugging(self, scan_id: int) -> bool:
        """Enable plugin debugging on an existing scan.

        Fetches current scan settings and adds plugin_debugging=True, preserving
        all other configuration (credentials, targets, etc.).

        Args:
            scan_id: The Tenable scan ID to update.

        Returns:
            True if the scan was updated successfully, False otherwise.
        """
        if not self._ensure_initialized():
            return False

        try:
            logger.info(f"Fetching current settings for scan {scan_id}...")
            details = self._tio.scans.details(scan_id)
            settings = details.get("settings", {})

            if settings.get("plugin_debugging"):
                logger.info("Plugin debugging is already enabled on this scan.")
                return True

            settings["plugin_debugging"] = True
            self._tio.scans.configure(scan_id, settings=settings)
            logger.info(f"✓ Plugin debugging enabled on scan {scan_id}")
            return True

        except Exception as e:
            logger.error(f"Failed to enable debugging on scan {scan_id}: {e}")
            return False

    def launch_targeted_scan(self, scan_id: int, host_ip: str) -> Optional[str]:
        """Launch a scan targeting a single host.

        Uses alt_targets to override the scan's normal target list, so only
        the specified host is scanned. This is faster than a full scan run.

        Args:
            scan_id: The Tenable scan ID to launch.
            host_ip: IP address of the single host to target.

        Returns:
            The scan UUID string on success, or None on failure.
        """
        if not self._ensure_initialized():
            return None

        try:
            logger.info(f"Launching scan {scan_id} targeting {host_ip}...")
            response = self._tio.scans.launch(scan_id, alt_targets=[host_ip])
            scan_uuid = response.get("scan_uuid") if isinstance(response, dict) else str(response)
            logger.info(f"✓ Scan launched (UUID: {scan_uuid})")
            return scan_uuid

        except Exception as e:
            logger.error(f"Failed to launch scan {scan_id}: {e}")
            return None

    def wait_for_completion(
        self,
        scan_id: int,
        timeout_seconds: int = 600,
        poll_interval: int = 15,
    ) -> bool:
        """Poll until the scan finishes or a timeout is reached.

        Args:
            scan_id: The Tenable scan ID to monitor.
            timeout_seconds: Maximum seconds to wait before giving up (default: 600).
            poll_interval: Seconds between status checks (default: 15).

        Returns:
            True if the scan completed successfully, False if it timed out,
            was aborted, or encountered an error.
        """
        if not self._ensure_initialized():
            return False

        deadline = time.time() + timeout_seconds
        elapsed = 0

        logger.info(f"Waiting for scan {scan_id} to complete (timeout: {timeout_seconds}s)...")

        while time.time() < deadline:
            try:
                details = self._tio.scans.details(scan_id)
                status = details.get("info", {}).get("status", "unknown")

                logger.debug(f"  Scan {scan_id} status: {status} (elapsed: {elapsed}s)")

                if status in _DONE_STATUSES:
                    logger.info(f"✓ Scan completed (status: {status}, elapsed: {elapsed}s)")
                    return True

                if status in _FAILED_STATUSES:
                    logger.error(f"Scan ended with status '{status}' after {elapsed}s")
                    return False

                if status not in _RUNNING_STATUSES:
                    logger.warning(f"Unexpected scan status '{status}' — continuing to poll")

            except Exception as e:
                logger.error(f"Error polling scan status: {e}")
                return False

            time.sleep(poll_interval)
            elapsed += poll_interval

        logger.error(f"Timed out waiting for scan {scan_id} after {timeout_seconds}s")
        return False

    def get_latest_history_id(self, scan_id: int) -> Optional[int]:
        """Get the history_id of the most recently completed scan run.

        Used after wait_for_completion to identify the new run for export.

        Args:
            scan_id: The Tenable scan ID.

        Returns:
            The history ID integer, or None if not found.
        """
        if not self._ensure_initialized():
            return None

        try:
            history = list(self._tio.scans.history(scan_id))
            completed = [h for h in history if h.get("status") in _DONE_STATUSES]
            if not completed:
                return None
            completed.sort(key=lambda h: h.get("time_end", 0), reverse=True)
            return completed[0].get("id")
        except Exception as e:
            logger.error(f"Error fetching history for scan {scan_id}: {e}")
            return None


def create_diagnostic_scan_config(
    host: str,
    base_config: Optional[ScanConfig] = None,
    enable_debug: bool = True,
    unsafe: bool = False,
) -> dict[str, Any]:
    """Generate a diagnostic scan configuration dict (Tenable API format).

    This produces a JSON structure suitable for importing into Tenable or
    passing to the scans.configure() API. It describes the settings that
    should differ from the base policy.

    Args:
        host: IP address to target.
        base_config: Optional base configuration to derive policy name from.
        enable_debug: Whether to enable plugin debugging (default: True).
        unsafe: When True, disables safe checks. Tenable does not recommend
            disabling safe checks in production — disruptive plugins can crash
            services or targets — so this defaults to False (safe checks ON).

    Returns:
        Scan configuration dict in Tenable API settings format.
    """
    name = f"Host Doctor Diagnostic — {host}"
    if base_config and base_config.scan_name:
        name = f"{base_config.scan_name} (Debug) — {host}"

    return {
        "name": name,
        "description": "Generated by Host Doctor for detailed single-host diagnostics",
        "targets": host,
        "settings": {
            "plugin_debugging": enable_debug,
            # Tenable advises against disabling safe checks in production; keep
            # them ON unless the caller explicitly opts into an unsafe scan.
            "safe_checks": not unsafe,
            "network_timeout": 10,
            "max_checks_per_host": 5,
        },
    }
