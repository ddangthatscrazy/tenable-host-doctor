# Tenable Host Doctor

Single-host diagnostic tool for Tenable scans. Analyzes why a specific host failed to scan properly — authentication failures, missing coverage, network issues, and policy misconfigurations.

## What It Does

**Problem it solves:** You have one problematic host in a scan and need to understand why it's not scanning correctly.

**Approach:**
1. Analyze local scan data (`.nessus` file, `nessus.db`, `.kb` files)
2. Compare scan configuration vs what actually happened
3. Detect specific failure patterns (SSH password, SMB invalid creds, registry denied)
4. Compare against OS-specific baseline expectations (Linux: 80-120 plugins, Windows: 80-150)
5. Identify root cause with specific evidence (plugin IDs, error messages, usernames)
6. Produce actionable remediation with test commands

**No API rate limits** - works entirely with local files (except optional scan creation).

## Getting Started

> **New here? Skip the manual steps below and use one of these instead:**
>
> 🤖 **[QUICKSTART_CLAUDE.md](QUICKSTART_CLAUDE.md)** — Using Claude (no LLM API key needed). Includes a one-step prompt you can paste directly into Claude to install and configure everything automatically.
>
> ⚡ **[QUICKSTART.md](QUICKSTART.md)** — Using your own LLM via LiteLLM (OpenAI, Anthropic, Ollama, etc.). Includes a one-step prompt for automated setup.

---

## Key Differences from Scan Doctor

| Feature | Scan Doctor | Host Doctor |
|---------|-------------|-------------|
| **Scope** | Whole scan health | Single host deep dive |
| **Data Source** | API-heavy (100+ calls) | Local files (1 export) |
| **Analysis** | Iterative LLM loop | Deterministic checks |
| **Use Case** | Broad triage | Root cause analysis |
| **Rate Limits** | Hits them easily | Avoids them |

## Workflow

```bash
# METHOD 1: Auto-fetch from Tenable (easiest - NEW!)
host-doctor analyze --scan-name "Production Scan" --host 192.168.1.100

# METHOD 2: Auto-fetch by scan ID
host-doctor analyze --scan-id 12345 --host 192.168.1.100

# METHOD 3: With local .nessus file
host-doctor analyze scan.nessus --host 192.168.1.100

# All methods support optional debug log fetching with --scan-id
host-doctor analyze --scan-name "Production Scan" --host 192.168.1.100 --scan-id 12345
```

**Auto-fetch requires API credentials:**
```bash
export TIO_ACCESS_KEY="your-access-key"
export TIO_SECRET_KEY="your-secret-key"
```

## Installation

Requires Python 3.9+.

```bash
git clone https://github.com/ddangthatscrazy/tenable-host-doctor
cd tenable-host-doctor

# Create a virtual environment (recommended)
python3 -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

pip install -e .
```

For auto-fetch (pull scans directly from Tenable without exporting a file):

```bash
pip install -e ".[api]"
```

### Optional: Access to Scanner Files

For advanced analysis, if you have access to the Nessus scanner filesystem:

```bash
# Copy files from scanner
scp scanner:/opt/nessus/var/nessus/users/admin/scans/12345/results.db ./
scp scanner:/opt/nessus/var/nessus/kbs/192.168.1.100.kb ./

# Analyze with additional context
host-doctor analyze scan_12345.nessus \
  --host 192.168.1.100 \
  --nessus-db results.db \
  --kb 192.168.1.100.kb
```

### Optional: Fetch Debug Logs via API

**NEW (2026-06-16):** Host Doctor can fetch debug logs and attachments via Tenable API:

```bash
# Configure API credentials
export TIO_ACCESS_KEY="your-access-key"
export TIO_SECRET_KEY="your-secret-key"

# Analyze with debug log fetching
host-doctor analyze scan_12345.nessus \
  --host 192.168.1.100 \
  --scan-id 12345

# This fetches:
# - SSH command execution logs
# - Authentication debugging details
# - Plugin error traces
# - Scanner internal errors
```

**Benefits:**
- See **exact SSH commands** Nessus ran
- Get **detailed auth failure reasons** (not just "failed")
- Identify **specific plugin errors** and missing tools
- **No scanner filesystem access** required

**Requirements:**
- API credentials (TIO_ACCESS_KEY/TIO_SECRET_KEY)
- Plugin debugging enabled in scan policy
- Scan results less than 60 days old

See [docs/ATTACHMENT_FETCHING.md](docs/ATTACHMENT_FETCHING.md) for full details.

## What It Checks

### Enhanced Authentication Detection (✨ Phase 1)
- ✅ **SSH password authentication failures** (plugin 104410 with specific parsing)
  - Extracts username, protocol, port, error message
  - Counts missing OS-specific local security check plugins
  - Provides SSH-specific remediation (sshd_config, account lock checks)
- ✅ **SMB invalid credentials** (plugin 21745 with specific parsing)
  - Detects domain vs local account issues
  - Counts Windows family plugin coverage
  - Cross-checks registry access (plugin 26917)
- ✅ **Windows registry access denied** (plugin 26917)
  - Identifies UAC/GPO restrictions
  - Provides LocalAccountTokenFilterPolicy guidance
- ✅ **Plugin coverage baseline comparison**
  - Linux credentialed: 80-120 plugins expected, 30+ OS family
  - Windows credentialed: 80-150 plugins expected, 50+ Windows family
  - Calculates coverage percentage and grade (A-F)
- ✅ **Missing critical plugin families**
  - Detects missing OS Local Security Checks (CentOS, Ubuntu, RedHat, etc.)
  - Detects missing Windows : Microsoft Bulletins
- ✅ **Minimal coverage detection** (< 10 plugins indicates severe issues)

### Configuration vs Results Analysis
- ✅ Credential configuration vs host type (local vs domain, SSH vs WMI)
- ✅ Plugin family coverage vs OS detected
- ✅ Timeout settings vs actual scan duration
- ✅ Port range coverage vs services found
- ✅ Safe checks setting vs environment type

### Authentication Deep Dive
- ✅ Which protocols were attempted (SSH, WMI, SNMP)
- ✅ Exact failure reason from plugin output
- ✅ Credential priority issues (low-priv tried first)
- ✅ Permission errors during authenticated checks

### Network & Performance
- ✅ Connectivity issues (timeouts, unreachable)
- ✅ Scan duration anomalies for this host
- ✅ Scanner placement issues (wrong network zone)
- ✅ MTU/fragmentation problems

### Plugin & Policy Issues
- ✅ Disabled plugin families needed for this OS
- ✅ Scanner version/plugin feed staleness
- ✅ Plugin crashes or errors specific to this host
- ✅ Registry service cleanup failures (Windows)

### Historical Comparison (with .kb file)
- ✅ What changed since last successful scan
- ✅ Credential degradation over time
- ✅ New firewall rules blocking access

## Architecture

```
host_doctor/
├── parsers/
│   ├── nessus.py         # .nessus XML parser
│   ├── nessusdb.py       # SQLite reader (optional)
│   └── kb.py             # .kb file parser (optional)
├── analyzers/
│   ├── config.py         # Extract scan configuration
│   ├── auth.py           # Authentication analysis
│   ├── network.py        # Network/timeout analysis
│   ├── policy.py         # Policy vs results checks
│   └── historical.py     # Compare with past scans
├── models.py             # Data classes
├── report.py             # HTML/markdown report generator
├── scan_creator.py       # Generate diagnostic scan configs
└── cli.py                # Command-line interface
```

**Design principles:**
- Deterministic analysis (no LLM loop)
- Local-first (minimal API usage)
- Fast (parse once, analyze many checks)
- Extensible (easy to add new analyzers)

## Data Sources

### .nessus File (Primary, Always Required)
- Export from Tenable UI or API
- Contains: hosts, vulnerabilities, plugin outputs, scan config
- **Advantage:** Complete scan results, plugin output text
- **Limitation:** Static snapshot, no historical data

### nessus.db (Optional, Scanner Access Required)
- SQLite database on scanner filesystem
- Location: `/opt/nessus/var/nessus/users/*/scans/*/results.db`
- **Advantage:** SQL queries, faster than XML, multi-scan history
- **Use when:** You have scanner SSH access

### .kb File (Optional, Scanner Access Required)
- Knowledge base - persistent host state
- Location: `/opt/nessus/var/nessus/kbs/<host_ip>.kb`
- **Advantage:** Historical comparison, "what changed?" analysis
- **Use when:** Host was scanning successfully before, now broken

## Example Output

```
Host Doctor Report: 192.168.1.100
Scan: Production Windows Scan (ID: 12345)
Status: ❌ Authentication Failed

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
ROOT CAUSE
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

🔴 CRITICAL: Credential Type Mismatch
   
   The scan used a local account (WORKGROUP\admin) but the target
   is a domain-joined Windows machine (CORP domain).
   
   Evidence:
   • Plugin 104410: "SMB login failed: NT_STATUS_LOGON_FAILURE"
   • Host OS: Windows Server 2019 (Domain: CORP)
   • Credential configured: Local account "admin"
   
   Fix:
   → Use domain credential: CORP\admin or admin@corp.local
   → OR use local admin with domain override disabled

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
CONFIGURATION ISSUES
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

🟡 WARNING: Plugin Family "Windows : Microsoft Bulletins" Disabled
   
   Authentication prerequisites are met but patch detection is disabled.
   
   Impact: Missing vulnerability findings (CVEs, MS advisories)
   
   Fix:
   → Enable "Windows" plugin family in scan policy
   → OR use "Advanced Scan" template (has all families enabled)

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
RECOMMENDED DIAGNOSTIC SCAN
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Current scan lacks detailed authentication logs.
Run this diagnostic scan for deeper analysis:

  host-doctor create-diagnostic-scan \
    --host 192.168.1.100 \
    --output diagnostic_scan.json \
    --enable-debug-logging

Then import diagnostic_scan.json to Tenable and run.
```

## Roadmap

**v0.1 - Core (MVP)**
- [x] Project structure
- [x] .nessus parser
- [x] Config extractor (plugin 19506)
- [x] Core analyzers (auth, network, policy, coverage)
- [x] HTML/Markdown/JSON report generation
- [x] CLI: `analyze` command
- [x] Auto-fetch from Tenable API (`--scan-name`, `--scan-id`)
- [x] Debug log and attachment fetching via API

**v0.2 - Enhanced**
- [ ] nessus.db support
- [ ] Diagnostic scan generator (`create-diagnostic-scan` command)
- [ ] Precheck: validate scan config before running

**v0.3 - Historical**
- [ ] .kb file parser
- [ ] Historical comparison ("what changed?")
- [ ] Credential degradation detection

**v0.4 - Polish**
- [ ] Interactive mode (ask follow-up questions)
- [ ] Export findings to Jira/ServiceNow
- [ ] Batch mode (analyze multiple hosts)

## Plugin Reference

Key plugin IDs used for diagnostics. These drive most of the analysis logic.

| Plugin ID | Name | What it tells you |
|-----------|------|-------------------|
| 19506 | Nessus Scan Information | Full scan config: credentials used, timeouts, port scanner type, debugging status |
| 84239 | Authentication Failure Debug Log | SSH commands attempted and exact errors — only present when debugging is enabled |
| 141118 | Target Credential Status — Valid Credentials | SSH authentication succeeded |
| 102094 | Microsoft Windows SMB Login Successful | Windows SMB/WMI authentication succeeded |
| 104410 | Credential Authentication Failure | Authentication failed — output contains exact error and protocol |
| 21745 | Authentication Failure (legacy) | Older auth failure format |
| 26917 | SMB Registry Access | Windows registry access succeeded — absence with valid SMB creds indicates UAC/GPO blocking |
| 117530 | Plugin Execution Errors | Plugin crashed or encountered errors on this host |
| 10114 | ICMP Destination Unreachable | Network path issues between scanner and host |
| 10180 | Ping Host Unresponsive | Host not responding to ICMP |

Presence of plugins from OS patch families ("Windows : Microsoft Bulletins", "Red Hat Local Security Checks", "Ubuntu Local Security Checks", etc.) is the strongest indicator that credentialed checks fully succeeded.

## Configuration

### Tenable API credentials (required for scan download and debug log fetching)

```bash
export TIO_ACCESS_KEY="your-access-key"
export TIO_SECRET_KEY="your-secret-key"
```

### LiteLLM model for AI enrichment (optional — falls back to deterministic analysis)

```bash
# Anthropic Claude
export SCAN_DOCTOR_MODEL="anthropic/claude-sonnet-4-6"
export ANTHROPIC_API_KEY="sk-ant-..."

# OpenAI
export SCAN_DOCTOR_MODEL="openai/gpt-4o"
export OPENAI_API_KEY="sk-..."

# Local via Ollama (free, no API key required)
export SCAN_DOCTOR_MODEL="ollama/llama3.1"
export SCAN_DOCTOR_API_BASE="http://localhost:11434"
```

If no model is configured, the tool runs in deterministic-only mode and still produces useful findings — just without the LLM narrative layer.

## Development

### Adding a new analyzer

Create a file in `host_doctor/analyzers/`:

```python
# host_doctor/analyzers/my_check.py
from host_doctor.models import Finding, FindingCategory, HostData, ScanConfig, Severity

def analyze_my_check(host_data: HostData, scan_config: ScanConfig) -> list[Finding]:
    findings = []

    if some_condition:
        findings.append(Finding(
            category=FindingCategory.CONFIGURATION,
            severity=Severity.HIGH,
            title="Issue title",
            description="What's wrong and why it matters",
            evidence=["Plugin 12345 output shows...", "Config has..."],
            remediation=["Step 1: ...", "Step 2: ..."],
            plugin_ids=[12345],
        ))

    return findings
```

Then call it from `host_doctor/agent/agent.py` in `_run_deterministic_analyzers()`.

### Adding a new agent tool

Add to `host_doctor/agent/tools.py`:

```python
def my_tool(host_data: HostData, scan_config: ScanConfig, param: str = "") -> dict:
    """One-line description the LLM will use to decide when to call this."""
    return {"result": ...}
```

Then register it in `DiagnosticAgent._register_tools()` and add its definition to `DiagnosticAgent._get_tool_definitions()` in `host_doctor/agent/agent.py`.

### Running tests

```bash
# Run all tests
pytest

# With coverage report
pytest --cov=host_doctor

# Single test file
pytest tests/test_auth.py -v
```

### Linting and formatting

```bash
black host_doctor tests
ruff check host_doctor tests
```

## License

MIT
