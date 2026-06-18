"""Fetch scan attachments from Tenable API.

This module retrieves debugging logs and other attachments that are not
included in the .nessus XML export but are available via the Tenable API.
"""

import logging
from io import BytesIO
from typing import Optional

from tenable.io import TenableIO

from host_doctor.config import config

logger = logging.getLogger(__name__)


class AttachmentFetcher:
    """Fetch scan attachments from Tenable Vulnerability Management API."""

    def __init__(self, tio: Optional[TenableIO] = None):
        """Initialize attachment fetcher.

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
                logger.debug(
                    "Tenable API credentials not configured. "
                    "Set TIO_ACCESS_KEY and TIO_SECRET_KEY to enable attachment fetching."
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
                logger.warning(f"Failed to initialize Tenable API client: {e}")
                return False

        self._initialized = True
        return True

    def get_debug_logs(
        self,
        scan_id: int,
        host_id: int,
        history_id: Optional[int] = None,
    ) -> Optional[str]:
        """Retrieve plugin 84239 debug logs for a host.

        These logs contain SSH command execution logs, authentication debugging,
        and detailed plugin execution traces when debugging is enabled in the scan.

        Args:
            scan_id: Scan ID or UUID
            host_id: Host ID from scan results
            history_id: Optional specific scan run ID

        Returns:
            Debug log content as string, or None if unavailable
        """
        if not self._ensure_initialized():
            return None

        try:
            # Get plugin output which may include attachment metadata
            logger.debug(
                f"Fetching plugin 84239 output for scan={scan_id}, "
                f"host={host_id}, history={history_id}"
            )

            output = self.tio.scans.plugin_output(
                scan_id=scan_id,
                host_id=host_id,
                plugin_id=84239,  # Debugging Log Report
                history_id=history_id,
            )

            # Check if attachment is present
            if not output or "outputs" not in output:
                logger.debug("No plugin output data returned")
                return None

            # Iterate through outputs to find attachment info
            for output_item in output.get("outputs", []):
                # Check for attachment metadata in various possible locations
                attachment_info = None

                # Check direct attachment field
                if "attachment" in output_item:
                    attachment_info = output_item["attachment"]

                # Check for compliance-style attachments
                elif "plugin_output" in output_item:
                    # Some attachments reference in the output text
                    plugin_text = output_item["plugin_output"]
                    if "attached" in plugin_text.lower():
                        logger.debug(
                            f"Found attachment reference in output: {plugin_text[:100]}"
                        )

                # If we found attachment metadata, download it
                if attachment_info and isinstance(attachment_info, dict):
                    attachment_id = attachment_info.get("id")
                    key = attachment_info.get("key")

                    if attachment_id and key:
                        logger.debug(
                            f"Downloading attachment {attachment_id} with key"
                        )
                        attachment_data = self.tio.scans.attachment(
                            scan_id=scan_id,
                            attachment_id=attachment_id,
                            key=key,
                        )

                        # Read and decode the attachment
                        if isinstance(attachment_data, BytesIO):
                            content = attachment_data.read().decode("utf-8", errors="replace")
                            logger.info(
                                f"Successfully fetched debug logs ({len(content)} bytes)"
                            )
                            return content

            logger.debug("No attachments found in plugin output")
            return None

        except Exception as e:
            logger.warning(f"Could not fetch debug logs: {e}")
            return None

    def get_nessusd_dump_errors(
        self,
        scan_id: int,
        host_id: int,
        history_id: Optional[int] = None,
    ) -> Optional[str]:
        """Retrieve plugin 117530 nessusd.dump error logs.

        These logs show which plugins encountered errors during execution.

        Args:
            scan_id: Scan ID or UUID
            host_id: Host ID from scan results
            history_id: Optional specific scan run ID

        Returns:
            Error log content as string, or None if unavailable
        """
        if not self._ensure_initialized():
            return None

        try:
            logger.debug(
                f"Fetching plugin 117530 output for scan={scan_id}, "
                f"host={host_id}, history={history_id}"
            )

            output = self.tio.scans.plugin_output(
                scan_id=scan_id,
                host_id=host_id,
                plugin_id=117530,  # Errors in nessusd.dump
                history_id=history_id,
            )

            # The error summary is in the plugin output text itself
            if output and "outputs" in output:
                for output_item in output.get("outputs", []):
                    if "plugin_output" in output_item:
                        return output_item["plugin_output"]

            return None

        except Exception as e:
            logger.warning(f"Could not fetch nessusd.dump errors: {e}")
            return None

    def _get_host_id_from_scan(
        self,
        scan_id: int,
        host_ip: str,
        history_id: Optional[int] = None,
    ) -> Optional[int]:
        """Get the host_id for a given IP/hostname from scan results.

        Args:
            scan_id: Scan ID
            host_ip: IP address or hostname of the host
            history_id: Optional specific scan run

        Returns:
            Host ID if found, None otherwise
        """
        if not self._ensure_initialized():
            return None

        try:
            # Get scan details which includes hosts
            kwargs = {"scan_id": scan_id}
            if history_id:
                kwargs["history_id"] = history_id

            results = self.tio.scans.results(**kwargs)

            # Search for matching host - API returns hostname field,
            # need to check against IP in .nessus file
            for host in results.get("hosts", []):
                hostname = host.get("hostname", "")
                # Match by hostname or if hostname looks like IP, also check that
                if hostname == host_ip:
                    logger.debug(f"Found host by hostname match: {hostname}")
                    return host.get("host_id")

                # Get the actual IP by fetching host details if needed
                # For now, try using host details API
                host_id = host.get("host_id")
                try:
                    # Quick check - get just the host properties
                    details = self.tio.scans.host_details(
                        scan_id=scan_id,
                        host_id=host_id,
                        history_id=history_id,
                    )
                    # Check info.host-ip or other IP fields
                    host_ip_value = details.get("info", {}).get("host-ip")
                    if host_ip_value == host_ip:
                        logger.debug(f"Found host {host_ip} with host_id {host_id}")
                        return host_id
                except Exception:
                    # If host details fails, continue
                    pass

            logger.warning(f"Host {host_ip} not found in scan {scan_id} results")
            return None

        except Exception as e:
            logger.warning(f"Could not get host_id for {host_ip}: {e}")
            return None

    def get_ssh_command_logs(
        self,
        scan_id: int,
        host_id: int,
        history_id: Optional[int] = None,
    ) -> Optional[str]:
        """Retrieve plugin 168017 SSH command logs for a host.

        These logs contain all SSH commands executed during the scan,
        including responses, errors, and privilege escalation details.

        Args:
            scan_id: Scan ID or UUID
            host_id: Host ID from scan results
            history_id: Optional specific scan run ID

        Returns:
            SSH command log content as JSON string, or None if unavailable
        """
        if not self._ensure_initialized():
            return None

        try:
            logger.debug(
                f"Fetching plugin 168017 output for scan={scan_id}, "
                f"host={host_id}, history={history_id}"
            )

            kwargs = {"scan_id": scan_id, "host_id": host_id, "plugin_id": 168017}
            if history_id:
                kwargs["history_id"] = history_id

            output = self.tio.scans.plugin_output(**kwargs)

            # Check for attachments in the ports structure
            if output and "outputs" in output:
                for output_item in output.get("outputs", []):
                    ports = output_item.get("ports", {})
                    for port_key, port_data in ports.items():
                        for host_info in port_data:
                            attachments = host_info.get("attachments", [])
                            if attachments:
                                # Get the first attachment (SSH commands JSON)
                                attachment_info = attachments[0]
                                attachment_id = attachment_info.get("id")
                                key = attachment_info.get("key")

                                if attachment_id and key:
                                    logger.debug(
                                        f"Downloading SSH command log attachment {attachment_id}"
                                    )
                                    attachment_data = self.tio.scans.attachment(
                                        scan_id=scan_id,
                                        attachment_id=attachment_id,
                                        key=key,
                                    )

                                    if isinstance(attachment_data, BytesIO):
                                        content = attachment_data.read().decode(
                                            "utf-8", errors="replace"
                                        )
                                        logger.info(
                                            f"Successfully fetched SSH command logs ({len(content)} bytes)"
                                        )
                                        return content

            logger.debug("No SSH command log attachments found")
            return None

        except Exception as e:
            logger.warning(f"Could not fetch SSH command logs: {e}")
            return None

    def get_launched_plugins(
        self,
        scan_id: int,
        host_id: int,
        history_id: Optional[int] = None,
    ) -> Optional[str]:
        """Retrieve plugin 112154 (Enumerate Launched Plugins) output for a host.

        Returns the list of plugins that actually launched during the scan, used
        to answer "why didn't this plugin run?". Mirrors get_ssh_command_logs and
        uses the verified scans.plugin_output API. There is no audit-trail endpoint
        in pyTenable's Tenable.io, so the audit trail is not fetched here.

        Args:
            scan_id: Scan ID or UUID
            host_id: Host ID from scan results
            history_id: Optional specific scan run ID

        Returns:
            Launched-plugins output text, or None if unavailable.
        """
        if not self._ensure_initialized():
            return None

        try:
            kwargs = {"scan_id": scan_id, "host_id": host_id, "plugin_id": 112154}
            if history_id:
                kwargs["history_id"] = history_id

            output = self.tio.scans.plugin_output(**kwargs)

            texts = []
            if output and "outputs" in output:
                for output_item in output.get("outputs", []):
                    text = output_item.get("plugin_output")
                    if text:
                        texts.append(text)
            if texts:
                content = "\n".join(texts)
                logger.info(f"Fetched launched-plugins list ({len(content)} bytes)")
                return content

            logger.debug("No plugin 112154 output found")
            return None

        except Exception as e:
            logger.warning(f"Could not fetch launched-plugins list: {e}")
            return None

    def get_all_attachments(
        self,
        scan_id: int,
        host_ip: str,
        history_id: Optional[int] = None,
    ) -> dict[str, str]:
        """Retrieve all available attachments for a host.

        This is a convenience method that fetches all known attachment types.

        Args:
            scan_id: Scan ID or UUID
            host_ip: IP address of the host (will be used to find host_id)
            history_id: Optional specific scan run ID

        Returns:
            Dictionary mapping attachment name to content
        """
        # First, get the host_id
        host_id = self._get_host_id_from_scan(scan_id, host_ip, history_id)
        if host_id is None:
            logger.warning(f"Cannot fetch attachments without host_id for {host_ip}")
            return {}

        attachments = {}

        # SSH command logs (plugin 168017)
        ssh_logs = self.get_ssh_command_logs(scan_id, host_id, history_id)
        if ssh_logs:
            attachments["ssh_commands"] = ssh_logs

        # Debug logs (plugin 84239)
        debug_logs = self.get_debug_logs(scan_id, host_id, history_id)
        if debug_logs:
            attachments["debug_logs"] = debug_logs

        # Nessusd dump errors (plugin 117530)
        dump_errors = self.get_nessusd_dump_errors(scan_id, host_id, history_id)
        if dump_errors:
            attachments["nessusd_dump_errors"] = dump_errors

        return attachments
