# Quick Start — Using Host Doctor with Claude

This guide is for users running Host Doctor alongside Claude (no LLM API key required). Claude acts as the AI layer — interpreting the deterministic findings, connecting the dots, and giving you plain-language recommendations.

## Requirements

- Python 3.9+
- Claude desktop app with the `host-doctor` skill installed
- A Tenable scan to analyze (file export or API credentials to auto-fetch)

## Step 1 — Install Host Doctor

```bash
git clone https://github.com/ddangthatscrazy/tenable-host-doctor
cd tenable-host-doctor

python3 -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

pip install -e .
```

## Step 2 — Install the Claude Skill

The Host Doctor skill enables Claude to interpret scan diagnostics. To install it:

1. Copy or symlink the `skill.md` file to your Claude skills directory:
   ```bash
   # Create skills directory if it doesn't exist
   mkdir -p ~/.claude/skills
   
   # Symlink the skill (recommended - picks up updates automatically)
   ln -s "$(pwd)/skill.md" ~/.claude/skills/host-doctor.md
   
   # Or copy it
   cp skill.md ~/.claude/skills/host-doctor.md
   ```

2. Restart Claude if it's already running

The skill will now be available as `/host-doctor` in your Claude conversations.

To let Host Doctor fetch scans directly from Tenable (no manual export needed):

```bash
pip install -e ".[api]"

export TIO_ACCESS_KEY="your-access-key"
export TIO_SECRET_KEY="your-secret-key"
```

## Step 3 — Get the scan data

**Option A: Auto-fetch by scan name or ID (easiest)**
```bash
host-doctor analyze --scan-name "Production Scan" --host 192.168.1.100
```

**Option B: Export manually from Tenable UI**
1. Open your scan in Tenable.io
2. Click **Export** → **Nessus**
3. Download the `.nessus` file, then:

```bash
host-doctor analyze scan.nessus --host 192.168.1.100
```

> **Tip:** The host identifier must match exactly how it appears in the scan — usually the IP address. If you get a "host not found" error, the tool will list all available hosts.

## Step 4 — Run the analysis

Host Doctor generates a JSON report that Claude can read and interpret:

```bash
host-doctor analyze --scan-name "Production Scan" --host 192.168.1.100 \
  --format json --output report.json
```

## Step 5 — Open Claude and invoke the skill

In the Claude desktop app, start a conversation and invoke the Host Doctor skill. Then share the `report.json` file and ask Claude to analyze it:

> "Analyze this Host Doctor report and tell me why this host isn't scanning correctly."

Claude will read the deterministic findings and give you:
- A plain-language explanation of what's wrong
- Prioritized recommendations for what to fix first
- Specific remediation steps tailored to your environment

## Step 6 — If debug data is missing

If Claude tells you that plugin debugging wasn't enabled in the scan, you have two options:

**With Tenable API credentials**, Host Doctor can handle it automatically:
```bash
host-doctor analyze --scan-name "Production Scan" --host 192.168.1.100 \
  --scan-id 12345 --auto-debug --format json --output report_debug.json
```

This will enable plugin debugging on the scan, re-run it against just that host, download the results, and re-analyze — all in one step. Bring the new `report_debug.json` back to Claude for a deeper analysis.

**Without API credentials**, Claude will walk you through enabling debugging manually in the Tenable UI, then you re-export and re-run the analysis.

## Common Questions

**Do I need an API key for Claude?**
No. The skill runs inside the Claude desktop app using your existing Claude account.

**What if I don't have Tenable API credentials?**
Export the `.nessus` file manually from the Tenable UI (Export → Nessus) and use that as input. The `--auto-debug` feature requires API credentials, but all other analysis works without them.

**How do I know what host identifier to use?**
Run this to list all hosts in a scan file:
```bash
python3 -c "
from pathlib import Path
from host_doctor.parsers.nessus import parse_nessus_file
scan = parse_nessus_file(Path('scan.nessus'))
for h in scan['hosts']:
    print(f'{h.host_ip}  {h.hostname or \"\"}')
"
```

## Further Reading

- `README.md` — full documentation and architecture
- `QUICKSTART.md` — CLI-first quickstart for users with their own LLM API key
- `skill.md` — the skill definition Claude uses to interpret Host Doctor output
