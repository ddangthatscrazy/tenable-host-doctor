# Quick Start Guide

## Requirements

- Python 3.9+
- A `.nessus` export file from Tenable (or Tenable API credentials for auto-fetch)

## Installation

```bash
git clone https://github.com/ddangthatscrazy/tenable-host-doctor
cd tenable-host-doctor

# Create a virtual environment (recommended)
python3 -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# Install
pip install -e .
```

To use auto-fetch (pull scans directly from Tenable without exporting a file):

```bash
pip install -e ".[api]"
```

## Basic Usage

### 1. Get a scan file

**Option A: Export from Tenable UI (no extra setup)**
1. Open the scan in Tenable.io
2. Click **Export** → **Nessus**
3. Download the `.nessus` file

**Option B: Auto-fetch from Tenable API**
```bash
export TIO_ACCESS_KEY="your-access-key"
export TIO_SECRET_KEY="your-secret-key"

# Then use --scan-name or --scan-id instead of a file
host-doctor analyze --scan-name "Production Scan" --host 192.168.1.100
```

### 2. Analyze a host

```bash
# Basic analysis (HTML output)
host-doctor analyze scan.nessus --host 192.168.1.100

# Markdown output for tickets
host-doctor analyze scan.nessus --host 192.168.1.100 \
  --format markdown --output report.md

# JSON for automation
host-doctor analyze scan.nessus --host 192.168.1.100 \
  --format json --output report.json

# Verbose mode
host-doctor analyze scan.nessus --host 192.168.1.100 -v
```

### 3. View the report

The tool generates a report with findings:
- **Critical/High** - Issues requiring immediate attention
- **Medium** - Configuration improvements
- **Low/Info** - Informational findings

Each finding includes:
- **Evidence** - Plugin IDs and outputs
- **Remediation** - Step-by-step fixes

## Example Output

```
✓ Analysis complete

Findings: 0 critical, 1 high, 3 medium, 1 low, 0 info

Report: host_192_168_1_100_report.html
```

## Common Findings

### Authentication Issues
- ❌ **Authentication Failure** - Wrong credentials or locked account
- ⚠️ **Partial Auth** - Credentials work but insufficient privileges
- ⚠️ **Creds Not Used** - Scan configured but auth not attempted

### Network Issues
- ❌ **Host Unreachable** - Offline, firewalled, or wrong IP
- ⚠️ **Timeout Patterns** - Network latency or packet loss
- ⚠️ **Limited Port Access** - Firewall blocking most ports

### Configuration Issues
- ⚠️ **Missing Plugin Families** - Wrong families for detected OS
- ⚠️ **Safe Checks on Lab** - Should be disabled for test environments
- ⚠️ **Stale Plugin Feed** - Scanner needs updates

## Finding Host IPs

If you don't know which host IP to use:

```bash
python3 -c "
from pathlib import Path
from host_doctor.parsers.nessus import parse_nessus_file

scan = parse_nessus_file(Path('scan.nessus'))
for host in scan['hosts']:
    print(f'{host.host_ip} - {host.hostname or \"no hostname\"} - {host.operating_system or \"unknown OS\"}')
"
```

## Advanced Usage

### With nessus.db (scanner access required)

```bash
# Copy from scanner
scp scanner:/opt/nessus/.../results.db ./

# Analyze with enhanced data
host-doctor analyze scan.nessus --host 192.168.1.100 \
  --nessus-db results.db
```

### With .kb file (historical comparison)

```bash
# Copy KB file
scp scanner:/opt/nessus/var/nessus/kbs/192.168.1.100.kb ./

# Compare with historical baseline
host-doctor analyze scan.nessus --host 192.168.1.100 \
  --kb 192.168.1.100.kb
```

## LLM Configuration (Optional)

Without an LLM configured, the tool runs deterministic analysis and still produces useful findings. To add AI narrative and deeper interpretation:

```bash
# Copy the example env file
cp .env.example .env

# Edit .env and set your provider:

# Anthropic Claude
SCAN_DOCTOR_MODEL=anthropic/claude-sonnet-4-6
ANTHROPIC_API_KEY=sk-ant-...

# OpenAI
SCAN_DOCTOR_MODEL=openai/gpt-4o
OPENAI_API_KEY=sk-...

# Local Ollama (free, no API key)
SCAN_DOCTOR_MODEL=ollama/llama3.1
SCAN_DOCTOR_API_BASE=http://localhost:11434
```

## Troubleshooting

### "File not found" error
- Check the file path is correct
- Use an absolute path: `/home/you/scans/scan.nessus`

### "Host not found" error
- Use the host listing script above to see exact IPs
- Check for leading zeros or IPv6 vs IPv4 differences

### "Parser error"
- Verify the file is a `.nessus` export, not a PDF or HTML report
- Try re-exporting from the Tenable UI

### No findings generated
- Expected if the scan is clean and well-configured
- Try `-v` to see analysis reasoning
- Confirm the host actually had issues in the scan

## Getting Help

- `README.md` — full documentation and architecture overview
- `skill.md` — instructions for using this tool via Claude
- `TODO.md` — known limitations and planned features
- File issues at the project repo
