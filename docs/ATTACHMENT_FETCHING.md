# Debug Log Attachment Fetching

## Overview

Host Doctor can now fetch and analyze **debug logs and attachments** from Tenable Vulnerability Management via API. This provides deep diagnostic information that is NOT included in `.nessus` exports:

- **SSH command execution logs**: Every command Nessus ran on the target
- **Authentication debugging**: Detailed auth failure reasons and handshake logs
- **Plugin execution traces**: What each plugin tried to do and why it failed
- **Scanner error logs**: Internal scanner errors from `nessusd.dump`

## Why This Matters

Debug logs answer critical questions like:

❓ **"What SSH commands did Nessus actually run?"**  
✅ See the exact command list, including OS detection, package queries, and security checks

❓ **"Why did authentication fail?"**  
✅ Get the actual error message from the SSH/SMB handshake

❓ **"Which plugins crashed or timed out?"**  
✅ See specific plugin IDs and error messages from the scanner

❓ **"Did Nessus even attempt to run X command?"**  
✅ Confirm whether the issue is missing credentials vs. missing permissions

## Requirements

### 1. Enable Plugin Debugging in Scan Policy

In your Tenable scan policy:
- **Advanced** → **Performance** → **Enable plugin debugging** (set to level 2-3)
- This increases scan time slightly but generates detailed logs

### 2. Configure API Credentials

Set environment variables:
```bash
export TIO_ACCESS_KEY="your-access-key"
export TIO_SECRET_KEY="your-secret-key"
```

Or create `.env` file:
```bash
TIO_ACCESS_KEY=your-access-key
TIO_SECRET_KEY=your-secret-key
```

### 3. Know Your Scan ID

Find your scan ID from Tenable UI URL:
```
https://cloud.tenable.com/scans/{scan_id}/hosts
```

Or use the API:
```bash
curl -H "X-ApiKeys: accessKey=xxx; secretKey=xxx" \
  https://cloud.tenable.com/scans | jq '.scans[] | {id, name}'
```

## Usage

### Basic Usage (No Attachments)

```bash
# Analyze without API attachments
host-doctor analyze scan.nessus --host 192.168.1.100
```

**Output:**
```
⚠ Note: Use --scan-id to fetch debug logs from Tenable API
       Debug logs contain SSH commands and authentication details
```

### With Attachment Fetching

```bash
# Fetch debug logs from API
host-doctor analyze scan.nessus \
  --host 192.168.1.100 \
  --scan-id 12345
```

**Output:**
```
✓ Fetched 2 attachment(s)
  • debug_logs: 45,832 bytes
  • nessusd_dump_errors: 1,203 bytes
```

### With Specific Scan Run

```bash
# Fetch from a specific scan history
host-doctor analyze scan.nessus \
  --host 192.168.1.100 \
  --scan-id 12345 \
  --history-id 67890
```

## What You Get

### 1. SSH Command Log

Debug logs show **every command** Nessus executed:

```
SSH commands executed during scan:

  • uname -a
  • cat /etc/os-release
  • dpkg -l
  • rpm -qa --qf '%{NAME}|%{EPOCH}|%{VERSION}|%{RELEASE}|%{ARCH}\n'
  • cat /etc/shadow
  • systemctl list-units --type=service --all
  ... and 247 more commands
```

**Use this to:**
- Verify expected commands were attempted
- Check for permission-denied errors
- See if OS-specific commands ran

### 2. Authentication Details

```
Authentication failures found in debug logs:

  • Authentication failed: Permission denied (publickey,password)
  • Login failed: User account locked
  • Password authentication failed: expired password
```

**Use this to:**
- Get exact error from SSH/SMB handshake
- Distinguish between wrong password vs. account lock
- See which auth methods were tried

### 3. Plugin Execution Errors

```
Plugin execution errors found:

  • Plugin 12345 error: Command not found: netstat
  • ERROR: Failed to open /proc/version: Permission denied
  • FATAL: Timeout waiting for command response
```

**Use this to:**
- Identify missing tools on target system
- Find permission issues post-authentication
- Detect scanner bugs or timeouts

## Testing Attachment Fetching

Use the standalone test script:

```bash
python test_attachment_fetch.py \
  --scan-id 12345 \
  --host-ip 192.168.1.100
```

**Output:**
```
=== Testing Attachment Fetch ===
Scan ID: 12345
Host IP: 192.168.1.100
History ID: latest

Fetching attachments...

✓ Found 1 attachment(s):

📎 debug_logs
   Size: 45,832 bytes
   Preview (first 500 chars):
   ------------------------------------------------------------
   [2026-06-16 14:30:45] SSH: Connecting to 192.168.1.100:22
   [2026-06-16 14:30:46] SSH: Authentication method: publickey
   [2026-06-16 14:30:46] SSH: Login successful as user 'root'
   [2026-06-16 14:30:47] SSH: Executing command: uname -a
   [2026-06-16 14:30:47] Result: Linux target 5.4.0-42-generic ...
   
=== Debug Log Analysis ===
Total commands: 253
Unique commands: 187

Command types:
  • os_detection: 8
  • package_management: 142
  • file_inspection: 67
  • network_config: 12
  • service_status: 24

Sample commands:
  • uname -a
  • cat /etc/os-release
  • dpkg -l
  • rpm -qa
  • systemctl list-units
```

## Limitations

### 1. 60-Day Window

Attachments are only available for scans **less than 60 days old**. Older scans must be re-run with debugging enabled.

### 2. Debugging Must Be Enabled

If debugging was **not enabled** in the original scan, no logs exist. You'll need to:
1. Enable plugin debugging in policy
2. Re-run the scan
3. Then fetch attachments

### 3. API Access Required

You cannot fetch attachments without API credentials. If you only have the `.nessus` file and no API access, this feature won't work.

## Integration with Analyzers

Debug logs are automatically analyzed when available:

```python
# In host_doctor/analyzers/debug_logs.py
findings = analyze_debug_logs(host_data, scan_config)
```

**Findings include:**
- `SSH Command Execution Log Available` (INFO)
- `Authentication Failures Detected` (HIGH)
- `Successful Authentication Confirmed` (INFO)
- `Plugin Execution Errors Detected` (MEDIUM)

## Troubleshooting

### "No attachments found"

**Possible causes:**
1. Plugin debugging not enabled in scan policy
2. Scan results older than 60 days
3. Host IP doesn't match exactly (check for hostname vs IP)
4. API credentials not configured

**Fix:**
```bash
# Check if debugging was enabled
grep "plugin debugging" scan.nessus

# Verify credentials work
curl -H "X-ApiKeys: accessKey=$TIO_ACCESS_KEY; secretKey=$TIO_SECRET_KEY" \
  https://cloud.tenable.com/scans
```

### "Could not get host_id for 192.168.1.100"

**Cause:** The host IP in the scan results doesn't match the IP you provided.

**Fix:**
```bash
# List all hosts in the scan
curl -H "X-ApiKeys: accessKey=xxx; secretKey=xxx" \
  https://cloud.tenable.com/scans/12345 | jq '.hosts[].hostname'
```

### "Failed to initialize Tenable API client"

**Cause:** Missing or invalid API credentials.

**Fix:**
```bash
# Verify credentials are set
echo $TIO_ACCESS_KEY
echo $TIO_SECRET_KEY

# Test API access
curl -H "X-ApiKeys: accessKey=$TIO_ACCESS_KEY; secretKey=$TIO_SECRET_KEY" \
  https://cloud.tenable.com/session
```

## API Implementation Details

Under the hood, Host Doctor:

1. **Gets host_id** from scan results:
   ```python
   results = tio.scans.results(scan_id)
   host_id = next(h["host_id"] for h in results["hosts"] 
                  if h["hostname"] == host_ip)
   ```

2. **Fetches plugin output** with attachment metadata:
   ```python
   output = tio.scans.plugin_output(scan_id, host_id, 84239)
   ```

3. **Downloads attachment** if present:
   ```python
   attachment = tio.scans.attachment(
       scan_id, 
       output["attachment"]["id"],
       output["attachment"]["key"]
   )
   ```

4. **Parses and analyzes** the log content with regex patterns

## Future Enhancements

Potential additions:

- [ ] Fetch **all plugin attachments** (not just debug logs)
- [ ] Parse **Windows WMI query logs** (similar to SSH)
- [ ] Extract **credential escalation attempts** (sudo logs)
- [ ] Show **network traffic patterns** from port scans
- [ ] Cache attachments locally to avoid re-fetching
- [ ] Support **Nessus Manager** (on-prem) API endpoints

## References

- [Tenable Scans API - Attachments](https://developer.tenable.com/reference/scans-attachments)
- [Plugin 84239 - Debugging Log Report](https://www.tenable.com/plugins/nessus/84239)
- [Plugin 117530 - Errors in nessusd.dump](https://www.tenable.com/plugins/nessus/117530)
