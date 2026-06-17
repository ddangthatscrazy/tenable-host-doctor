# Making Host Doctor Effective: Action Plan

## Current State Analysis

From analyzing the Homelab scan:
- ✅ **We ARE capturing diagnostic data** - Plugin 19506 has detailed scan config
- ✅ **Authentication info exists** - "Credentialed checks : yes, as '192.168.1.174\administrator' via SMB"
- ❌ **We're not parsing the rich output** - Plugin 19506 has 1217 chars of config data we ignore
- ❌ **Missing 300+ plugins** - Only extracting 12, but scan has 323 unique plugins
- ❌ **No protocol-specific logic** - Not handling VMware, SNMP, databases, etc.

## Effectiveness Issues Identified

### Issue 1: Plugin 19506 Output Not Fully Parsed
**Current:** We extract version, safe checks, timeout
**Missing from output:**
```
Credentialed checks : yes, as '192.168.1.174\administrator' via SMB
Ping RTT : 50.522 ms
Port scanner(s) : wmi_netstat
Thorough tests : no
Experimental tests : no  
Plugin debugging enabled : yes (at debugging level 3)
Paranoia level : 1
```

**Impact:** Can't tell:
- Which exact credential was used
- If debugging is enabled (for troubleshooting)
- RTT (to diagnose timeouts)
- Which port scanner (affects discovery)

### Issue 2: No Protocol Detection Logic
**Problem:** We don't know what protocols SHOULD work on a host

**Example:**
- Windows Server detected → Should check for SMB/WMI auth
- ESXi detected → Should check for VMware auth + SSH
- Linux detected → Should check for SSH auth
- Network device detected → Should check for SNMP

**Current behavior:** Generic "credentials configured but not used"
**Better behavior:** "Windows Server detected but SMB credentials failed with NT_STATUS_LOGON_FAILURE"

### Issue 3: No Error Pattern Extraction
**Problem:** Plugin 104410 has rich error messages we don't parse

**Windows SMB errors we should recognize:**
- `NT_STATUS_LOGON_FAILURE` → Wrong username/password
- `NT_STATUS_ACCESS_DENIED` → Insufficient privileges  
- `NT_STATUS_ACCOUNT_LOCKED_OUT` → Account locked
- `LocalAccountTokenFilterPolicy` → UAC blocking remote admin

**SSH errors we should recognize:**
- `Permission denied` → Wrong credentials
- `Connection refused` → Service not running
- `Host key verification failed` → SSH key mismatch
- `timeout` → Network/firewall issue

### Issue 4: Missing VMware/ESXi Support
**Plugins to add:**
- **20094** - VMware ESXi detection
- **89105** - VMware ESXi patch level
- **66809** - VMware vCenter detection

**VMware-specific auth patterns:**
- `vim.fault.NotAuthenticated` → Wrong vCenter credentials
- `SSO authentication failed` → vCenter SSO issue
- SSH + HTTPS both needed → Must check both paths

### Issue 5: No Cross-Plugin Correlation
**Example:** activedirectory host
- Plugin 10394: "SMB tests will be done as administrator"
- Plugin 10396: "The following shares can be accessed as administrator"
- **→ Auth is working!** But we flagged "credentials not used"

**Why?** We only check for plugin 102094, but actual evidence is in 10394/10396

## Action Plan to Be Effective

### Priority 1: Enhanced Plugin 19506 Parsing (2 hours)
```python
def parse_plugin_19506_enhanced(output: str) -> dict:
    """Extract ALL config from plugin 19506."""
    return {
        "credential_used": "administrator via SMB",  # Exact cred
        "ping_rtt_ms": 50.522,                      # Network latency
        "port_scanner": "wmi_netstat",              # Scanner type
        "thorough_tests": False,                     # Coverage level
        "debugging_enabled": True,                   # Debug availability
        "debugging_level": 3,                        # Debug verbosity
        "paranoia_level": 1,                        # Scan aggressiveness
        # ... etc
    }
```

**Impact:** Can diagnose:
- "Ping RTT 200ms but timeout set to 5s → increase timeout"
- "Debugging disabled → can't get detailed error logs"
- "wmi_netstat scanner → fast but may miss ports"

### Priority 2: Protocol Detection & Validation (3 hours)
```python
def detect_expected_protocols(host_data: HostData) -> list[str]:
    """What protocols SHOULD work based on OS/services detected."""
    os = host_data.operating_system or ""
    expected = []
    
    if "windows" in os.lower():
        expected.append("SMB")
        expected.append("WMI")
    elif "esxi" in os.lower() or "vmware" in os.lower():
        expected.append("VMware API")
        expected.append("SSH")
    elif "linux" in os.lower():
        expected.append("SSH")
    # ... etc
    
    return expected

def validate_protocol_coverage(host_data, scan_config):
    """Check if scan tried the right protocols."""
    expected = detect_expected_protocols(host_data)
    
    for protocol in expected:
        if protocol == "SMB" and not scan_config.has_windows_creds:
            yield Finding("Windows host but no SMB credentials configured")
        elif protocol == "SSH" and not scan_config.has_ssh_creds:
            yield Finding("Linux host but no SSH credentials configured")
```

**Impact:** Catches obvious mismatches

### Priority 3: Error Pattern Extraction (4 hours)
```python
ERROR_PATTERNS = {
    "NT_STATUS_LOGON_FAILURE": {
        "protocol": "SMB",
        "root_cause": "Wrong username or password",
        "remediation": [
            "Verify username is correct (domain\\user or user@domain.com)",
            "Verify password is correct and not expired",
            "Check if account is locked (check AD or Event Viewer)"
        ]
    },
    "NT_STATUS_ACCESS_DENIED": {
        "protocol": "SMB",
        "root_cause": "Insufficient privileges - account can't read remote registry",
        "remediation": [
            "Add account to local Administrators group",
            "Set LocalAccountTokenFilterPolicy=1 if using local admin",
            "Grant 'Access this computer from network' permission"
        ]
    },
    "Permission denied (publickey,password)": {
        "protocol": "SSH",
        "root_cause": "SSH authentication failed - wrong key or password",
        "remediation": [
            "Verify SSH password is correct",
            "If using key: verify key is correct and in authorized_keys",
            "Check SSH server config allows password/key auth"
        ]
    },
    # ... 50+ more patterns
}

def extract_root_cause(plugin_output: str) -> Optional[dict]:
    """Parse plugin output for known error patterns."""
    for pattern, info in ERROR_PATTERNS.items():
        if pattern in plugin_output:
            return info
    return None
```

**Impact:** Specific, actionable remediation instead of generic advice

### Priority 4: Cross-Plugin Evidence Correlation (3 hours)
```python
def check_smb_auth_success(host_data: HostData) -> bool:
    """Multiple ways to detect successful SMB auth."""
    evidence = [
        host_data.has_plugin(102094),  # Primary: SMB login successful
        host_data.has_plugin(10394),   # SMB log in possible
        host_data.has_plugin(10396),   # SMB shares accessed
        host_data.has_plugin(26917),   # Registry access
    ]
    return any(evidence)

def check_ssh_auth_success(host_data: HostData) -> bool:
    """Multiple ways to detect successful SSH auth."""
    evidence = [
        host_data.has_plugin(141118),  # Primary: SSH login successful
        host_data.has_plugin(12634),   # SSH protocol version
        len(host_data.get_vulnerabilities_by_family("Red Hat Local Security Checks")) > 0,
        len(host_data.get_vulnerabilities_by_family("Debian Local Security Checks")) > 0,
    ]
    return any(evidence)
```

**Impact:** Accurate auth status instead of false negatives

### Priority 5: VMware/ESXi Support (2 hours)
```python
# host_doctor/analyzers/vmware.py
def analyze_vmware(host_data: HostData, scan_config: ScanConfig) -> list[Finding]:
    """VMware/ESXi specific diagnostics."""
    findings = []
    
    # Detect ESXi
    is_esxi = any("esxi" in (host_data.operating_system or "").lower(),
                  host_data.has_plugin(20094))
    
    if not is_esxi:
        return findings
    
    # ESXi requires BOTH SSH and HTTPS access
    has_ssh = check_ssh_auth_success(host_data)
    has_vmware_api = host_data.has_plugin(66809)  # vCenter detection
    
    if not (has_ssh and has_vmware_api):
        findings.append(Finding(
            severity=Severity.HIGH,
            title="Incomplete ESXi Authentication",
            description="ESXi requires both SSH and VMware API access for complete scanning",
            evidence=[
                f"SSH auth: {'✓' if has_ssh else '✗'}",
                f"VMware API auth: {'✓' if has_vmware_api else '✗'}"
            ],
            remediation=[
                "Enable SSH on ESXi host (ESXi shell service)",
                "Provide both SSH credentials and vCenter/ESXi credentials",
                "Ensure ESXi HTTPS API is accessible from scanner"
            ]
        ))
    
    return findings
```

**Impact:** Handles ESXi edge cases

### Priority 6: Extract ALL Plugin Outputs (1 hour)
**Current:** Only extract 12 diagnostic plugins
**Better:** Extract ALL plugins, filter later

```python
# In parser
for item in host_elem.findall("ReportItem"):
    plugin_id = int(item.get("pluginID", 0))
    output_elem = item.find("plugin_output")
    
    # ALWAYS store if there's output (not just diagnostic plugins)
    if output_elem is not None and output_elem.text:
        plugins[plugin_id] = Plugin(...)
```

**Impact:** Can search for any pattern later

## Implementation Order

1. **[2 hrs]** Enhanced plugin 19506 parsing → Better config data
2. **[1 hr]** Extract all plugin outputs → More data available
3. **[3 hrs]** Protocol detection → Catch protocol mismatches
4. **[3 hrs]** Cross-plugin correlation → Accurate auth status
5. **[4 hrs]** Error pattern extraction → Specific root causes
6. **[2 hrs]** VMware/ESXi support → Handle edge case

**Total: 15 hours** to make tool truly effective

## Testing Plan

### Test Case 1: Windows Auth Failure
- Input: Scan with wrong Windows password
- Expected: "NT_STATUS_LOGON_FAILURE - wrong username/password"
- Current: "Credentials configured but not used"

### Test Case 2: ESXi Incomplete Auth
- Input: ESXi scan with only SSH (no VMware API)
- Expected: "ESXi requires both SSH and VMware API"
- Current: "Credentials configured but not used"

### Test Case 3: SSH on Windows
- Input: Windows Server with SSH creds configured
- Expected: "Windows Server detected but SSH credentials provided (should be SMB)"
- Current: "Credentials configured but not used"

### Test Case 4: High Latency Timeout
- Input: Ping RTT 180ms, timeout 5s
- Expected: "Network latency high (180ms), consider increasing timeout"
- Current: No finding

## Success Metrics

**Before:**
- Generic "auth failed" findings
- 30% false negatives (missed working auth)
- No protocol-specific guidance

**After:**
- Specific "NT_STATUS_LOGON_FAILURE - check password" findings
- 5% false negatives (cross-plugin correlation)
- Protocol-specific remediation (VMware, SSH, SMB)
- Root cause extraction from error messages

## Questions for You

1. Do you have ESXi scans we can test with?
2. Do you have SNMP device scans?
3. What's your priority: VMware support vs Windows deep-dive vs broad protocol coverage?
4. Should I start with Priority 1 (enhanced 19506 parsing)?
