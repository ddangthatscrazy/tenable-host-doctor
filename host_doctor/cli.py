"""Command-line interface for Host Doctor."""

import sys
from pathlib import Path
from typing import Optional

import click
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn

console = Console()


@click.group()
@click.version_option(version="0.1.0", prog_name="host-doctor")
def main():
    """Tenable Host Doctor - Single-host diagnostic tool."""
    pass


@main.command()
@click.argument("nessus_file", required=False, type=click.Path(path_type=Path))
@click.option("--host", required=True, help="IP address or hostname of host to analyze. Must match exactly how the host appears in the scan — use the IP if Nessus did not resolve a DNS name for the host.")
@click.option("--scan-id", type=int, help="Scan ID (used to fetch .nessus or attachments)")
@click.option("--scan-name", type=str, help="Scan name to lookup and fetch")
@click.option("--history-id", type=int, help="History ID for specific scan run")
@click.option("--nessus-db", type=click.Path(exists=True, path_type=Path),
              help="Optional: nessus.db SQLite file from scanner")
@click.option("--kb", type=click.Path(exists=True, path_type=Path),
              help="Optional: .kb file for historical comparison")
@click.option("--output", "-o", type=click.Path(path_type=Path),
              help="Output file path (default: host_<ip>_report.html)")
@click.option("--format", type=click.Choice(["html", "markdown", "json"]),
              default="html", help="Report format")
@click.option("--auto-debug", is_flag=True,
              help="Automatically enable plugin debugging and re-scan if debug data is missing "
                   "(requires --scan-id and API credentials)")
@click.option("--verbose", "-v", is_flag=True, help="Verbose output")
def analyze(
    nessus_file: Optional[Path],
    host: str,
    scan_id: Optional[int],
    scan_name: Optional[str],
    history_id: Optional[int],
    nessus_db: Optional[Path],
    kb: Optional[Path],
    output: Optional[Path],
    format: str,
    auto_debug: bool,
    verbose: bool,
):
    """Analyze a single host from a Nessus scan.

    Performs deep diagnostic analysis on why a specific host failed to scan
    properly or has incomplete coverage.

    THREE WAYS TO PROVIDE SCAN DATA:

    1. FROM LOCAL FILE:
        host-doctor analyze scan.nessus --host 192.168.1.100

    2. FROM SCAN NAME (auto-fetches latest):
        host-doctor analyze --scan-name "Production Scan" --host 192.168.1.100

    3. FROM SCAN ID (auto-fetches):
        host-doctor analyze --scan-id 12345 --host 192.168.1.100

    Auto-fetch requires TIO_ACCESS_KEY/TIO_SECRET_KEY environment variables.

    WHAT IT ANALYZES:
        • Authentication failures (SSH, SMB, credentials)
        • Missing plugin coverage vs OS baseline
        • Network connectivity and timeouts
        • Configuration mismatches (wrong credential type, etc.)
        • Plugin execution errors

    WITH API ACCESS YOU ALSO GET:
        • Exact SSH commands Nessus executed
        • Detailed authentication failure reasons
        • Plugin error traces and missing tools
        • Scanner internal errors from nessusd.dump
    """
    console.print(f"\n[bold]Tenable Host Doctor[/bold] - Analyzing {host}\n")

    # Validate input: need either file path OR scan-id/scan-name
    if not nessus_file and not scan_id and not scan_name:
        console.print("[red]Error:[/red] Must provide either:")
        console.print("  • A .nessus file path (positional argument)")
        console.print("  • --scan-id <id> to fetch from Tenable")
        console.print("  • --scan-name <name> to fetch from Tenable")
        sys.exit(1)

    # Import here to avoid slow startup
    from host_doctor.parsers.nessus import parse_nessus_file
    from host_doctor.report import generate_report

    # Track temp files that need cleanup
    temp_nessus_file = None

    try:
        report, output = _run_analysis(
            nessus_file=nessus_file,
            host=host,
            scan_id=scan_id,
            scan_name=scan_name,
            history_id=history_id,
            nessus_db=nessus_db,
            kb=kb,
            output=output,
            format=format,
            verbose=verbose,
            parse_nessus_file=parse_nessus_file,
            generate_report=generate_report,
        )

        # Print summary
        console.print(f"\n[bold green]✓ Analysis complete[/bold green]\n")
        console.print(
            f"Findings: {report.critical_count} critical, "
            f"{report.high_count} high, {report.medium_count} medium, "
            f"{report.low_count} low, {report.info_count} info"
        )
        console.print(f"\nReport: [cyan]{output}[/cyan]\n")

        # Debug loop — runs if scan lacks plugin debugging data
        if report.needs_diagnostic_scan:
            _run_debug_loop(
                report=report,
                host=host,
                scan_id=scan_id,
                history_id=history_id,
                output=output,
                format=format,
                verbose=verbose,
                auto_debug=auto_debug,
                parse_nessus_file=parse_nessus_file,
                generate_report=generate_report,
            )

        # Exit code based on severity
        exit_code = 0
        if report.critical_count > 0:
            exit_code = 2
        elif report.high_count > 0:
            exit_code = 1

        sys.exit(exit_code)

    except Exception as e:
        console.print(f"\n[red]Error:[/red] {e}")
        if verbose:
            console.print_exception()
        sys.exit(1)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _run_analysis(
    *,
    nessus_file,
    host,
    scan_id,
    scan_name,
    history_id,
    nessus_db,
    kb,
    output,
    format,
    verbose,
    parse_nessus_file,
    generate_report,
    label_suffix: str = "",
):
    """Core analysis pipeline. Returns (report, output_path).

    Extracted so it can be called twice — once for the initial analysis and
    once for the post-debug re-analysis.
    """
    temp_nessus_file = None

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:

        # Step 1: Get .nessus file (from disk or fetch from API)
        if not nessus_file:
            task = progress.add_task("Fetching scan from Tenable API...", total=None)

            from host_doctor.parsers.scan_fetcher import ScanFetcher
            fetcher = ScanFetcher()

            if scan_name:
                console.print(f"[cyan]Fetching scan:[/cyan] {scan_name}")
                nessus_file = fetcher.fetch_scan(
                    scan_identifier=scan_name,
                    history_id=history_id,
                )
            elif scan_id:
                console.print(f"[cyan]Fetching scan ID:[/cyan] {scan_id}")
                nessus_file = fetcher.fetch_scan(
                    scan_identifier=scan_id,
                    history_id=history_id,
                )

            if not nessus_file:
                console.print("[red]Error:[/red] Failed to fetch scan from Tenable API")
                console.print("\nMake sure:")
                console.print("  • TIO_ACCESS_KEY and TIO_SECRET_KEY are set")
                console.print("  • The scan name/ID exists and has completed runs")
                console.print("  • You have permission to access the scan")
                sys.exit(1)

            temp_nessus_file = nessus_file
            progress.update(task, description=f"✓ Downloaded: {nessus_file.name}")

            # Resolve scan_id from name if not already known
            if not scan_id and scan_name:
                scan_info = fetcher.find_scan_by_name(scan_name)
                if scan_info:
                    scan_id = scan_info.get("id")

        # Verify file
        if not nessus_file.exists():
            console.print(f"[red]Error:[/red] File not found: {nessus_file}")
            sys.exit(1)

        # Parse
        task = progress.add_task("Parsing .nessus file...", total=None)
        scan_data = parse_nessus_file(nessus_file)

        # Find target host (IP or hostname, case-insensitive)
        host_data = None
        for h in scan_data["hosts"]:
            if h.host_ip == host or (h.hostname and h.hostname.lower() == host.lower()):
                host_data = h
                break

        if not host_data:
            console.print(f"[red]Error:[/red] Host '{host}' not found in scan data")
            console.print(
                "[yellow]Tip:[/yellow] Nessus records hosts by the identifier used during scanning. "
                "If DNS resolution was not enabled in the scan policy, use the IP address instead of a hostname."
            )
            available = []
            for h in scan_data["hosts"]:
                if h.hostname and h.hostname != h.host_ip:
                    available.append(f"{h.host_ip} ({h.hostname})")
                else:
                    available.append(h.host_ip)
            console.print(f"\nAvailable hosts: {', '.join(available[:20])}")
            if len(available) > 20:
                console.print(f"... and {len(available) - 20} more")
            sys.exit(1)

        progress.update(task, description="✓ Parsed .nessus file")

        scan_config = scan_data["scan_config"]

        # Fetch attachments if scan_id provided
        if scan_id:
            task = progress.add_task("Fetching debug logs from API...", total=None)
            from host_doctor.parsers.attachments import AttachmentFetcher
            att_fetcher = AttachmentFetcher()
            try:
                attachments = att_fetcher.get_all_attachments(
                    scan_id=scan_id,
                    host_ip=host,
                    history_id=history_id,
                )
                if attachments:
                    host_data.attachments.update(attachments)
                    progress.update(task, description=f"✓ Fetched {len(attachments)} attachment(s)")
                    for att_name, att_content in attachments.items():
                        console.print(f"  • {att_name}: {len(att_content)} bytes")
                else:
                    progress.update(
                        task,
                        description="⚠ No attachments (debugging may not be enabled)",
                    )
            except Exception as e:
                if verbose:
                    console.print_exception()
                progress.update(task, description=f"⚠ Could not fetch attachments: {e}")
        else:
            console.print(
                "[yellow]Note:[/yellow] Use --scan-id to fetch debug logs from Tenable API\n"
            )

        # Run agent
        task = progress.add_task("Running AI diagnostic agent...", total=None)
        from host_doctor.agent.agent import DiagnosticAgent
        from host_doctor.config import config as host_config

        agent = DiagnosticAgent(
            host_data=host_data,
            scan_config=scan_config,
            model=host_config.SCAN_DOCTOR_MODEL,
            verbose=verbose,
        )
        report = agent.run()
        report.nessus_file = str(nessus_file)
        report.nessus_db_used = nessus_db is not None
        report.kb_file_used = kb is not None
        progress.update(task, description=f"✓ Agent completed — {len(report.findings)} findings")

        # Generate report
        task = progress.add_task("Generating report...", total=None)
        if not output:
            ip_safe = host.replace(".", "_")
            suffix = f"_{label_suffix}" if label_suffix else ""
            output = Path(f"host_{ip_safe}_report{suffix}.{format}")

        generate_report(report, output, format)
        progress.update(task, description=f"✓ Generated report: {output}")

    # Cleanup temp .nessus
    if temp_nessus_file and temp_nessus_file.exists():
        try:
            temp_nessus_file.unlink()
            if verbose:
                console.print(f"[dim]Cleaned up: {temp_nessus_file}[/dim]")
        except Exception:
            pass

    return report, output


def _print_debug_recommendation(host_ip: str, has_api: bool) -> None:
    """Print the 'enable plugin debugging' recommendation panel."""
    manual_steps = (
        f"[bold]To get a deeper analysis:[/bold]\n\n"
        f"  1. In Tenable, open this scan → More → Configure\n"
        f"  2. Under Settings → Assessment, enable [bold]Plugin debugging[/bold]\n"
        f"  3. Launch the scan targeting only [cyan]{host_ip}[/cyan]\n"
        f"  4. Export the new .nessus and re-run:\n"
        f"     [dim]host-doctor analyze <new_file> --host {host_ip}[/dim]"
    )
    if has_api:
        manual_steps += (
            f"\n\n[bold]Or let host-doctor do it automatically:[/bold]\n"
            f"  Re-run with [cyan]--auto-debug --scan-id <id>[/cyan]"
        )

    console.print(
        Panel(
            manual_steps,
            title="[yellow]⚠ Recommendation: Enable Plugin Debugging[/yellow]",
            border_style="yellow",
            padding=(1, 2),
        )
    )


def _run_debug_loop(
    *,
    report,
    host,
    scan_id,
    history_id,
    output,
    format,
    verbose,
    auto_debug,
    parse_nessus_file,
    generate_report,
) -> None:
    """Handle the debug loop after initial analysis.

    If API creds are available and scan_id is known, offers (or automatically
    performs) enabling plugin debugging, re-launching the scan, and re-analyzing.
    Falls back to a printed recommendation if API is unavailable.
    """
    from host_doctor.config import config as host_config

    has_api = bool(scan_id and host_config.has_tenable_api_config())

    if not has_api:
        # No API — print instructions and return
        _print_debug_recommendation(host, has_api=False)
        return

    # API available — offer or auto-proceed
    if not auto_debug:
        _print_debug_recommendation(host, has_api=True)
        console.print()
        proceed = click.confirm(
            "Would you like host-doctor to enable plugin debugging, re-scan, and re-analyze automatically?",
            default=False,
        )
        if not proceed:
            return

    # Run the API-driven debug loop
    console.print()
    _execute_debug_loop(
        host=host,
        scan_id=scan_id,
        output=output,
        format=format,
        verbose=verbose,
        parse_nessus_file=parse_nessus_file,
        generate_report=generate_report,
    )


def _execute_debug_loop(
    *,
    host,
    scan_id,
    output,
    format,
    verbose,
    parse_nessus_file,
    generate_report,
) -> None:
    """Run the four-step automated debug loop using the Tenable API."""
    try:
        from host_doctor.scan_creator import ScanManager
    except ImportError:
        console.print(
            "[red]Error:[/red] pytenable is required for --auto-debug.\n"
            "Run: pip install -e '.[api]'"
        )
        _print_debug_recommendation(host, has_api=False)
        return

    manager = ScanManager()
    scan_uuid = None

    try:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:

            # Step 1: Enable debugging
            task = progress.add_task("[1/4] Enabling plugin debugging...", total=None)
            if not manager.enable_debugging(scan_id):
                progress.update(task, description="[1/4] ✗ Failed to enable plugin debugging")
                raise RuntimeError("Could not enable plugin debugging on scan")
            progress.update(task, description="[1/4] ✓ Plugin debugging enabled")

            # Step 2: Launch targeted scan
            task = progress.add_task(f"[2/4] Launching targeted scan against {host}...", total=None)
            scan_uuid = manager.launch_targeted_scan(scan_id, host)
            if not scan_uuid:
                progress.update(task, description="[2/4] ✗ Failed to launch scan")
                raise RuntimeError("Could not launch targeted scan")
            progress.update(task, description=f"[2/4] ✓ Scan launched (UUID: {scan_uuid})")

            # Step 3: Wait for completion
            task = progress.add_task("[3/4] Waiting for scan to complete...", total=None)
            completed = manager.wait_for_completion(scan_id, timeout_seconds=900, poll_interval=15)
            if not completed:
                progress.update(task, description="[3/4] ✗ Scan did not complete in time")
                raise RuntimeError(
                    f"Scan did not complete within 15 minutes. "
                    f"Check scan status manually (UUID: {scan_uuid})"
                )
            progress.update(task, description="[3/4] ✓ Scan completed")

            # Step 4: Download new .nessus
            task = progress.add_task("[4/4] Downloading new scan results...", total=None)
            from host_doctor.parsers.scan_fetcher import ScanFetcher
            fetcher = ScanFetcher()
            new_history_id = manager.get_latest_history_id(scan_id)
            new_nessus = fetcher.export_scan(scan_id, history_id=new_history_id)
            if not new_nessus:
                progress.update(task, description="[4/4] ✗ Failed to download scan results")
                raise RuntimeError("Could not download scan results after debug run")
            progress.update(task, description=f"[4/4] ✓ Downloaded: {new_nessus.name}")

    except KeyboardInterrupt:
        console.print(f"\n[yellow]Interrupted.[/yellow] Scan UUID: [cyan]{scan_uuid}[/cyan]")
        console.print("Check scan status in Tenable and re-run host-doctor once complete.")
        return
    except RuntimeError as e:
        console.print(f"\n[red]Debug loop failed:[/red] {e}")
        _print_debug_recommendation(host, has_api=True)
        return
    except Exception as e:
        if verbose:
            console.print_exception()
        console.print(f"\n[red]Unexpected error during debug loop:[/red] {e}")
        _print_debug_recommendation(host, has_api=True)
        return

    # Re-analyze with the new file
    console.print("\n[bold]Re-analyzing with debug data...[/bold]\n")
    ip_safe = host.replace(".", "_")
    debug_output = output.parent / f"host_{ip_safe}_report_debug.{format}"

    try:
        debug_report, debug_output = _run_analysis(
            nessus_file=new_nessus,
            host=host,
            scan_id=scan_id,
            scan_name=None,
            history_id=new_history_id,
            nessus_db=None,
            kb=None,
            output=debug_output,
            format=format,
            verbose=verbose,
            label_suffix="debug",
            parse_nessus_file=parse_nessus_file,
            generate_report=generate_report,
        )

        console.print(f"\n[bold green]✓ Debug analysis complete[/bold green]\n")
        console.print(
            f"Findings: {debug_report.critical_count} critical, "
            f"{debug_report.high_count} high, {debug_report.medium_count} medium, "
            f"{debug_report.low_count} low, {debug_report.info_count} info"
        )
        console.print(f"\nDebug report: [cyan]{debug_output}[/cyan]\n")

    except Exception as e:
        if verbose:
            console.print_exception()
        console.print(f"\n[red]Re-analysis failed:[/red] {e}")
        console.print(f"The debug scan ran successfully. Re-export manually and run:")
        console.print(f"  host-doctor analyze <file> --host {host} --scan-id {scan_id}")
    finally:
        # Clean up downloaded debug .nessus
        if new_nessus and new_nessus.exists():
            try:
                new_nessus.unlink()
            except Exception:
                pass


@main.command()
@click.option("--host", required=True, help="IP address to scan")
@click.option("--base-config", type=click.Path(exists=True, path_type=Path),
              help="Base .nessus file to derive config from")
@click.option("--output", "-o", required=True, type=click.Path(path_type=Path),
              help="Output scan configuration JSON file")
@click.option("--enable-debug-logging", is_flag=True,
              help="Enable verbose plugin logging")
def create_diagnostic_scan(
    host: str,
    base_config: Optional[Path],
    output: Path,
    enable_debug_logging: bool,
):
    """Generate a diagnostic scan configuration for a problematic host.

    Creates a targeted scan config with diagnostic plugins, verbose logging,
    and extended timeouts. Import the resulting JSON into Tenable to run.

    Example:
        host-doctor create-diagnostic-scan --host 192.168.1.100 \\
          --base-config scan.nessus --output diag.json
    """
    console.print(f"\n[bold]Creating diagnostic scan config[/bold] for {host}\n")

    try:
        from host_doctor.scan_creator import create_diagnostic_scan_config
        import json

        base_scan_config = None
        if base_config:
            from host_doctor.parsers.nessus import parse_nessus_file
            scan_data = parse_nessus_file(base_config)
            base_scan_config = scan_data.get("scan_config")

        config = create_diagnostic_scan_config(
            host=host,
            base_config=base_scan_config,
            enable_debug=enable_debug_logging,
        )

        with open(output, "w") as f:
            json.dump(config, f, indent=2)

        console.print(f"[green]✓[/green] Diagnostic scan config written to: {output}")
        console.print("\nNext steps:")
        console.print("1. Import this config to Tenable (or use API)")
        console.print("2. Run the diagnostic scan")
        console.print("3. Export results as .nessus")
        console.print(f"4. Run: host-doctor analyze <file> --host {host}\n")

    except Exception as e:
        console.print(f"\n[red]Error:[/red] {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
