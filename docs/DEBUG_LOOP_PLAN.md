# Debug Loop Implementation Plan

## Overview

The debug loop is the interactive cycle that detects when a scan lacks plugin debugging,
recommends or automatically enables it, launches a targeted re-scan, and re-analyzes the results.

There are four pieces to build, in dependency order:

1. **Detection** — analyzer that detects missing debug data and flags the report
2. **scan_creator.py** — replace the stub with real API calls to configure + launch scans
3. **Agent wiring** — pass `needs_diagnostic_scan` through to the report
4. **CLI loop** — interactive prompt after report generation that drives the full cycle

---

## Piece 1: Debug Detection Analyzer

**File:** `host_doctor/analyzers/diagnostics.py` (new file)

Create a `detect_missing_debug_data(host_data: HostData, scan_config: ScanConfig) -> list[Finding]`
function. It should return a `Finding` (severity=MEDIUM, category=MISSING_DIAGNOSTICS) when ALL of
these are true:

- Auth appears to have failed OR coverage is below baseline (i.e., there is something worth
  diagnosing that debug logs would help with)
- `scan_config.debugging_enabled` is False or None
- Plugin 84239 (auth debug log) is absent from `host_data`

The finding should:
- Title: `"Plugin Debugging Not Enabled"`
- Description: explain that without debugging, only high-level failure signals are available — the
  exact SSH commands attempted, error codes, and which credential steps failed are not visible
- Evidence: `["Plugin 84239 (Authentication Failure Debug Log) not present", "scan_config.debugging_enabled = False"]`
- Remediation:
  1. Enable "Plugin debugging" in the scan policy (Settings → Assessment → General → check "Enable plugin debugging")
  2. Re-run the scan targeting only this host for faster results
  3. Re-export the .nessus file and re-run Host Doctor for a deeper analysis
- `plugin_ids=[84239]`

Also add a `should_recommend_debug_scan(host_data, scan_config, findings) -> bool` helper that
returns True when the above conditions are met. This will be used by the agent and CLI.

**Call site:** Add `detect_missing_debug_data` to `agent.py`'s `_run_deterministic_analyzers()`,
alongside the existing analyzer calls.

---

## Piece 2: scan_creator.py — Real Implementation

**File:** `host_doctor/scan_creator.py` (replace stub)

Replace the current stub with a `ScanManager` class that wraps the Tenable API for the three
operations the debug loop needs. All methods should follow the same lazy-init pattern as
`ScanFetcher` — import pytenable only when needed and fail gracefully if not installed.

### 2a. `enable_debugging(scan_id: int) -> bool`

Fetches current scan settings, adds `"plugin_debugging": True` to the settings dict, and saves
them back via `tio.scans.configure()`. Returns True on success.

The pytenable call is:
```python
# Get existing settings first to avoid clobbering other config
details = tio.scans.details(scan_id)
settings = details.get("settings", {})
settings["plugin_debugging"] = True
tio.scans.configure(scan_id, settings=settings)
```

Important: preserve all existing settings — do not pass only `plugin_debugging`. Tenable's
configure endpoint replaces the full settings dict.

### 2b. `launch_targeted_scan(scan_id: int, host_ip: str) -> Optional[str]`

Launches the scan against a single host using `alt_targets`. Returns the scan UUID (needed for
polling), or None on failure.

```python
response = tio.scans.launch(scan_id, alt_targets=[host_ip])
# response is a dict with 'scan_uuid'
return response.get("scan_uuid")
```

### 2c. `wait_for_completion(scan_id: int, timeout_seconds: int = 600, poll_interval: int = 15) -> bool`

Polls `tio.scans.details(scan_id)["info"]["status"]` every `poll_interval` seconds until status
is `"completed"` or `"canceled"`. Returns True if completed, False if timed out or errored.

Terminal statuses to watch for: `"completed"`, `"canceled"`, `"imported"` (treat as done).
Keep polling on: `"running"`, `"pending"`, `"resuming"`.
Fail immediately on: `"aborted"`, `"empty"`.

### 2d. Keep the existing `create_diagnostic_scan_config()` function

It is still called by the `create-diagnostic-scan` CLI command. Leave it in place but rename it
as a standalone function (not a method), so both the class and the legacy CLI command can coexist.

---

## Piece 3: Wire `needs_diagnostic_scan` into the Agent

**File:** `host_doctor/agent/agent.py`

In the `run()` method, after `findings = self._extract_findings_from_conversation()`, check
whether any finding has `category == FindingCategory.MISSING_DIAGNOSTICS` and
`title == "Plugin Debugging Not Enabled"`. If so, set `report.needs_diagnostic_scan = True`.

```python
report.needs_diagnostic_scan = any(
    f.category == FindingCategory.MISSING_DIAGNOSTICS
    and "Plugin Debugging" in f.title
    for f in findings
)
```

This is all that is needed here — the field already exists on `DiagnosticReport` and the report
templates already serialize it.

Also fix the hardcoded default model string on line 29:
```python
model: str = "anthropic/claude-sonnet-4-6",
```

---

## Piece 4: CLI Interactive Debug Loop

**File:** `host_doctor/cli.py`

After the report is generated and printed (after the `console.print("Report: ...")` line), add
the debug loop. This entire block only runs if `report.needs_diagnostic_scan is True`.

### 4a. Without API credentials — print recommendation only

If `TIO_ACCESS_KEY` / `TIO_SECRET_KEY` are not configured, print a clear recommendation block
and exit normally:

```
╭─ Recommendation: Enable Plugin Debugging ──────────────────────────────╮
│                                                                         │
│  This scan lacks plugin debugging data. Without it, Host Doctor can     │
│  identify that authentication likely failed but cannot see the exact    │
│  SSH commands attempted or detailed error codes.                        │
│                                                                         │
│  To get a deeper analysis:                                              │
│  1. In Tenable, open this scan policy → Settings → Assessment           │
│  2. Enable "Plugin debugging"                                           │
│  3. Run the scan again, targeting only: <host_ip>                       │
│  4. Re-export the .nessus file and re-run host-doctor                   │
│                                                                         │
│  Tip: Add TIO_ACCESS_KEY + TIO_SECRET_KEY to let host-doctor do this   │
│  automatically.                                                         │
╰─────────────────────────────────────────────────────────────────────────╯
```

### 4b. With API credentials — interactive offer

If API credentials ARE configured AND `scan_id` is known, prompt the user:

```
Plugin debugging is not enabled. Would you like host-doctor to:
  1. Enable plugin debugging on this scan
  2. Launch a targeted re-scan against <host_ip>
  3. Wait for it to complete and re-analyze automatically

[y/N]:
```

Use `click.confirm()` for the prompt. Default to No.

If the user says yes, run this sequence using `ScanManager`:

```
[1/4] Enabling plugin debugging on scan <scan_id>...  ✓
[2/4] Launching targeted scan against <host_ip>...    ✓ (scan UUID: xxx)
[3/4] Waiting for scan to complete...                 ✓ (completed in 4m 12s)
[4/4] Downloading and re-analyzing...
```

Steps 1-3 use `ScanManager`. Step 4 uses `ScanFetcher.export_scan()` (already implemented) to
download the new .nessus, then runs the full analysis pipeline again and generates a second report
with a `_debug` suffix in the filename (e.g., `host_192_168_1_100_report_debug.html`).

On any failure (API error, timeout, etc.), print the error and fall back to the manual
recommendation from 4a — never crash, always leave the user with actionable next steps.

### CLI flag for non-interactive use

Add `--auto-debug` flag to the `analyze` command:

```python
@click.option("--auto-debug", is_flag=True,
              help="Automatically enable debugging and re-scan if debug data is missing (requires API credentials)")
```

When `--auto-debug` is set, skip the `click.confirm()` prompt and proceed directly to the API
steps. This enables scripted/automated use.

---

## Error Handling Requirements

- If `pytenable` is not installed (no `[api]` extra), catch the `ImportError` and print:
  `"Auto-debug requires the [api] extra: pip install -e '.[api]'"` then fall back to the manual
  recommendation.
- If the scan has no history (brand new scan or all runs aborted), `wait_for_completion` should
  return False with a clear log message.
- If the user interrupts with Ctrl+C during the wait, catch `KeyboardInterrupt`, print the
  scan UUID so they can check status manually, and exit cleanly.

---

## File Change Summary

| File | Change |
|------|--------|
| `host_doctor/analyzers/diagnostics.py` | Create — detection logic |
| `host_doctor/scan_creator.py` | Replace stub with `ScanManager` class |
| `host_doctor/agent/agent.py` | Set `needs_diagnostic_scan`; fix default model string |
| `host_doctor/cli.py` | Add debug loop after report; add `--auto-debug` flag |

No changes needed to `models.py`, `report.py`, or the existing analyzers.

---

## Testing Checklist

After implementation, verify:

- [ ] `detect_missing_debug_data` returns a finding when plugin 84239 is absent and auth failed
- [ ] `detect_missing_debug_data` returns nothing when debugging was already on (plugin 84239 present)
- [ ] `report.needs_diagnostic_scan` is True in the JSON report output when the finding is present
- [ ] CLI prints the recommendation box when debugging is missing and no API creds are set
- [ ] CLI prompts and runs the loop when API creds are present
- [ ] `--auto-debug` skips the prompt
- [ ] A failed API call during the loop falls back gracefully to the manual recommendation
- [ ] The re-analysis produces a second report with `_debug` suffix
