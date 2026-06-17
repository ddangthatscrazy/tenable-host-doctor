# Plugin Enhancement Plan

## Problem: Missing Diagnostic Data

We currently only extract 12 plugins. Real diagnostics require 100+ plugins covering:
- All authentication protocols
- All error conditions
- Service detection results
- Network path analysis
- Configuration validation

## Solution: Comprehensive Plugin Taxonomy

### 1. Authentication Plugins by Protocol

#### SSH Authentication (Linux/Unix)
- **141118** - SSH login successful
- **12634** - SSH protocol version check
- **22964** - SSH weak MAC algorithms
- **71049** - SSH weak encryption
- **10881** - SSH protocol banner
- **46215** - SSH key exchange
- **90317** - SSH host key change detection

#### Windows Authentication (SMB/WMI)
- **102094** - Windows SMB login successful
- **104410** - Credential authentication failure
- **21745** - Patch assessment failed
- **26917** - Windows registry access
- **26920** - Windows SMB LAN Manager
- **10394** - SMB share enumeration
- **10399** - SMB NULL session

#### VMware/ESXi Authentication
- **20094** - VMware ESXi detection
- **89105** - VMware ESXi patch level
- **66809** - VMware vCenter detection
- **80480** - ESXi shell service detection
- **20089** - VMware VM detection
- **Need to research:** ESXi-specific auth failure plugins

#### SNMP Authentication
- **10264** - SNMP agent default community names
- **41028** - SNMP v3 authentication
- **10263** - SNMP query
- **Need to research:** SNMP v3 auth failure plugins

#### Database Authentication
- **10674** - MySQL server detection
- **10144** - Oracle TNS Listener detection
- **10144** - MSSQL server detection
- **Need to research:** Database-specific auth plugins

### 2. Error and Diagnostic Plugins

#### General Errors
- **117530** - Errors in nessusd.dump
- **84239** - Authentication failure debugging log
- **19506** - Nessus scan information

#### Service Detection
- **22964** - Service detection plugins
- **11219** - Nessus SYN scanner
- **10335** - Traceroute information
- **12053** - Host fully qualified domain name (FQDN)

#### Network Issues
- **10114** - ICMP timestamp
- **10180** - Ping host
- **10287** - Traceroute information
- **35716** - DNS server hostname disclosure

### 3. Configuration Validation Plugins

#### Patch Assessment
- **21643** - Patch assessment available
- **21745** - Patch assessment failed
- **110095** - No credential issues

#### Security Configuration
- **26917** - Microsoft Windows SMB registry access
- **90317** - SSH host key change

### 4. Protocol-Specific Patterns to Extract

#### SSH Errors
```
Pattern: "Permission denied"
Root cause: Wrong credentials

Pattern: "Connection refused"
Root cause: SSH service not running or firewall

Pattern: "Host key verification failed"
Root cause: SSH key mismatch

Pattern: "No supported authentication methods"
Root cause: Key-based required but password provided
```

#### Windows/SMB Errors
```
Pattern: "NT_STATUS_LOGON_FAILURE"
Root cause: Wrong username or password

Pattern: "NT_STATUS_ACCESS_DENIED"
Root cause: Insufficient privileges

Pattern: "NT_STATUS_ACCOUNT_LOCKED_OUT"
Root cause: Account locked

Pattern: "LocalAccountTokenFilterPolicy"
Root cause: UAC blocking remote admin
```

#### VMware/ESXi Patterns
```
Pattern: "SSO authentication failed"
Root cause: Wrong vCenter credentials

Pattern: "Host not licensed"
Root cause: ESXi license issue

Pattern: "vim.fault.NotAuthenticated"
Root cause: Session expired or wrong creds
```

#### SNMP Patterns
```
Pattern: "authorizationError"
Root cause: Wrong community string or user

Pattern: "Authentication failed"
Root cause: Wrong auth protocol or credentials

Pattern: "Timeout"
Root cause: SNMP service not running or firewall
```

## Implementation Plan

### Step 1: Expand Plugin Extraction
Change from fixed list to categories:
```python
# Instead of just 12 plugins, extract by category
AUTH_PLUGINS = range(100000, 150000)  # All auth-related
ERROR_PLUGINS = [117530, 84239, ...]
SERVICE_DETECTION = [10000, 11219, 22964, ...]
```

### Step 2: Build Plugin Knowledge Base
```python
PLUGIN_KNOWLEDGE = {
    104410: {
        "name": "Credential Authentication Failure",
        "category": "authentication",
        "protocol": "windows_smb",
        "patterns": {
            "NT_STATUS_LOGON_FAILURE": "Wrong username/password",
            "NT_STATUS_ACCESS_DENIED": "Insufficient privileges",
            "NT_STATUS_ACCOUNT_LOCKED": "Account locked",
        }
    },
    141118: {
        "name": "SSH Login Successful",
        "category": "authentication",
        "protocol": "ssh",
        "indicates": "successful_auth"
    },
    # ... hundreds more
}
```

### Step 3: Pattern Matchers
```python
def extract_root_cause_from_output(plugin_id: int, output: str) -> dict:
    """Parse plugin output for root cause patterns."""
    plugin_info = PLUGIN_KNOWLEDGE.get(plugin_id, {})
    patterns = plugin_info.get("patterns", {})
    
    for pattern, diagnosis in patterns.items():
        if pattern in output:
            return {
                "pattern_matched": pattern,
                "root_cause": diagnosis,
                "confidence": "high"
            }
    return {}
```

### Step 4: Protocol-Specific Analyzers
```python
# host_doctor/analyzers/vmware.py
def analyze_vmware_auth(host_data, scan_config):
    """VMware/ESXi specific authentication analysis."""
    # Check for ESXi detection
    # Check for vCenter detection
    # Analyze VMware-specific auth plugins
    # Parse ESXi error messages
    pass

# host_doctor/analyzers/snmp.py
def analyze_snmp_auth(host_data, scan_config):
    """SNMP specific authentication analysis."""
    pass
```

### Step 5: Cross-Plugin Correlation
```python
def correlate_auth_failure(host_data):
    """Cross-reference multiple plugins for deeper diagnosis."""
    
    # Example: SSH port open + auth failure = creds wrong
    # vs: SSH port closed + auth failure = service not running
    
    has_ssh_port = any(v.port == 22 for v in host_data.vulnerabilities)
    has_auth_failure = host_data.has_plugin(104410)
    
    if has_auth_failure and not has_ssh_port:
        return "SSH service not running or firewalled"
    elif has_auth_failure and has_ssh_port:
        return "SSH running but credentials failed"
```

## Next Actions

1. **Research VMware/ESXi plugins** - Find exact plugin IDs for ESXi auth
2. **Build comprehensive plugin list** - Extract from Tenable plugin feed
3. **Parse plugin outputs for patterns** - Build regex matchers
4. **Add protocol-specific analyzers** - Start with VMware, SNMP
5. **Test with real edge cases** - ESXi scans, SNMP scans, etc.

## Questions to Answer

1. What plugins specifically detect VMware/ESXi authentication?
2. What error patterns appear in ESXi auth failures?
3. How do we detect "wrong protocol" issues (SSH creds on Windows host)?
4. What plugins indicate network path issues vs credential issues?
5. How do we detect "credentials worked but insufficient privileges"?
