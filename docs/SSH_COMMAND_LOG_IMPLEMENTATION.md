# SSH Command Log Fetching - Implementation Summary

## What Was Built

Added **API-based attachment fetching** to Host Doctor, enabling access to debug logs and SSH command traces that are not included in `.nessus` exports.

## New Files Created

1. **`host_doctor/parsers/attachments.py`** (229 lines)
   - `AttachmentFetcher` class for API operations
   - Methods: `get_debug_logs()`, `get_nessusd_dump_errors()`, `get_all_attachments()`
   - Auto-discovers host_id from IP address
   - Graceful degradation when API unavailable

2. **`host_doctor/analyzers/debug_logs.py`** (335 lines)
   - Parses SSH command logs from debug output
   - Extracts authentication attempts and failures
   - Identifies plugin execution errors
   - Generates findings with evidence/remediation
   - Helper: `extract_ssh_command_summary()` for stats

3. **`test_attachment_fetch.py`** (71 lines)
   - Standalone test script
   - Usage: `python test_attachment_fetch.py --scan-id X --host-ip Y`
   - Shows what attachments are available
   - Displays command summary statistics

4. **`docs/ATTACHMENT_FETCHING.md`** (395 lines)
   - Complete user documentation
   - Requirements and setup
   - Usage examples
   - Troubleshooting guide
   - API implementation details

## Files Modified

1. **`host_doctor/models.py`**
   - Added `attachments: dict[str, str]` field to `HostData`
   - Added `history_id: Optional[int]` to `ScanConfig` for API calls

2. **`host_doctor/cli.py`**
   - Added `--scan-id` and `--history-id` options to `analyze` command
   - Integrated `AttachmentFetcher` with progress display
   - Shows helpful message when API not used

3. **`host_doctor/analyzers/__init__.py`**
   - Exported `analyze_debug_logs` function

4. **`README.md`**
   - Added "Optional: Fetch Debug Logs via API" section
   - Updated workflow examples

## How It Works

### Architecture

```
User Command
    ↓
CLI (host_doctor/cli.py)
    ↓
AttachmentFetcher (parsers/attachments.py)
    ↓
Tenable API (via pytenable)
    ├─ scans.results() → get host_id
    ├─ scans.plugin_output(84239) → get attachment metadata
    └─ scans.attachment() → download debug logs
    ↓
HostData.attachments["debug_logs"]
    ↓
DebugLogAnalyzer (analyzers/debug_logs.py)
    ├─ Parse SSH commands
    ├─ Parse auth attempts
    └─ Parse plugin errors
    ↓
Findings with evidence/remediation
```

### API Flow

1. **Discover host_id**: Match IP address against scan results
2. **Get plugin output**: Query plugin 84239 (Debugging Log Report)
3. **Check for attachment**: Look for `attachment` metadata in response
4. **Download attachment**: Use attachment_id and key from metadata
5. **Parse content**: Extract SSH commands, auth events, errors

### Graceful Degradation

- Works without API credentials (skips attachment fetching)
- Works without debugging enabled (skips debug log analysis)
- Works with old scans >60 days (warns user)
- Continues analysis if attachment fetch fails

## What Debug Logs Contain

When plugin debugging is enabled (level 2-3), logs include:

### 1. SSH Command Execution
```
SSH: Executing command: uname -a
Result: Linux target 5.4.0-42-generic #46-Ubuntu SMP x86_64 GNU/Linux
SSH: Executing command: cat /etc/os-release
Result: NAME="Ubuntu"
        VERSION="20.04.2 LTS (Focal Fossa)"
```

### 2. Authentication Details
```
SSH: Connecting to 192.168.1.100:22
SSH: Authentication method: publickey
Authentication failed: Permission denied (publickey,password)
Trying password authentication...
Login successful as user 'root'
```

### 3. Plugin Execution
```
Plugin 12345: Running check for CVE-2021-1234
Plugin 12345: Command: dpkg -l | grep vulnerable-package
Plugin 12345: Result: (empty)
Plugin 12345: Not vulnerable
```

### 4. Errors and Warnings
```
ERROR: Failed to execute: netstat -an
ERROR: Command not found: netstat
WARNING: Timeout waiting for command response (30s)
```

## Value Proposition

### Before (Without Attachments)
```
Finding: SSH Authentication Failed
Evidence: Plugin 104410 reported "Authentication failure"
```
**Problem:** User doesn't know WHY it failed

### After (With Attachments)
```
Finding: Authentication Failures Detected in Debug Logs
Evidence:
  • Authentication failed: Permission denied (publickey,password)
  • Login failed: User account locked
  • SSH key authentication failed: invalid key format
  
Remediation:
  • Check if account is locked: passwd -S username
  • Verify SSH key permissions: ls -la ~/.ssh/
  • Check sshd_config for AllowUsers restrictions
```
**Result:** User knows exactly what to fix

## Configuration Requirements

### For Users

1. **Enable plugin debugging** in scan policy:
   - Advanced → Performance → Enable plugin debugging (level 2-3)

2. **Set API credentials**:
   ```bash
   export TIO_ACCESS_KEY="xxx"
   export TIO_SECRET_KEY="xxx"
   ```

3. **Know scan ID** (from URL or API):
   ```
   https://cloud.tenable.com/scans/{scan_id}/hosts
   ```

### For Developers

No changes needed to existing code. The feature:
- Automatically detects API credentials
- Gracefully skips if unavailable
- Integrates with existing analyzer framework
- Adds findings to standard report output

## Usage Examples

### Basic (No API)
```bash
host-doctor analyze scan.nessus --host 192.168.1.100
# Output: "Note: Use --scan-id to fetch debug logs"
```

### With API Attachments
```bash
host-doctor analyze scan.nessus \
  --host 192.168.1.100 \
  --scan-id 12345
# Output: "✓ Fetched 2 attachment(s)"
#         "  • debug_logs: 45,832 bytes"
```

### Test Attachment Availability
```bash
python test_attachment_fetch.py \
  --scan-id 12345 \
  --host-ip 192.168.1.100
# Shows: attachment preview, command summary, analysis
```

## Limitations

1. **60-day retention**: Attachments only available for recent scans
2. **Debugging required**: Must be enabled before scan runs
3. **API access**: Requires TIO credentials
4. **Plugin 84239**: Only works if this plugin runs (needs debugging enabled)

## Future Enhancements

Potential additions:

- [ ] **Windows WMI logs**: Parse SMB/WMI command traces (similar to SSH)
- [ ] **Credential escalation**: Extract sudo/UAC attempt logs
- [ ] **Port scan details**: Network traffic patterns from port enumeration
- [ ] **Compliance attachments**: Audit policy and registry dumps
- [ ] **Local caching**: Cache attachments to avoid re-fetching
- [ ] **Nessus Manager**: Support on-prem API endpoints
- [ ] **Bulk fetching**: Download attachments for all hosts in one call

## Testing Checklist

- [x] Test with debugging enabled scan
- [ ] Test with debugging disabled (should skip gracefully)
- [ ] Test with old scan >60 days (should warn)
- [ ] Test without API credentials (should skip)
- [ ] Test with invalid scan ID (should error gracefully)
- [ ] Test with invalid host IP (should warn)
- [ ] Test SSH command parsing with real logs
- [ ] Test auth failure detection
- [ ] Test plugin error extraction
- [ ] Test CLI progress display
- [ ] Test standalone test script

## Documentation

All documentation provided:

1. **Code docstrings**: Every function has Args/Returns/Raises
2. **User guide**: `docs/ATTACHMENT_FETCHING.md` (395 lines)
3. **README update**: Quick start and feature overview
4. **Test script**: Shows how to use the API
5. **This summary**: Implementation architecture and design

## Deployment Notes

### Dependencies

No new dependencies required! Uses existing:
- `tenable-io` (pytenable) - already in requirements
- Python standard library (re, logging, io)

### Backward Compatibility

100% backward compatible:
- Existing workflows work unchanged
- New feature is opt-in (requires --scan-id)
- No breaking changes to existing code

### Security Considerations

- API credentials stored in env vars (not in code/files)
- Attachments are temporary (in-memory, not saved to disk by default)
- No sensitive data logged (API keys are redacted)
- Uses official Tenable SDK (handles auth/SSL properly)

## Success Metrics

This feature is successful if users can:

1. ✅ See exact SSH commands Nessus attempted
2. ✅ Get specific auth failure reasons (not just "failed")
3. ✅ Identify missing tools/commands on target
4. ✅ Distinguish between "wrong password" vs "account locked"
5. ✅ Debug incomplete scans without scanner filesystem access

---

**Status**: Implementation complete, ready for testing
**Date**: 2026-06-16
**Author**: Host Doctor Development Team
