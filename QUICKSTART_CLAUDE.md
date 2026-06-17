# Quick Start — Using Host Doctor with Claude

## One-Step Installation Prompt

Copy and paste the following prompt into Claude to have it install and validate Host Doctor automatically:

```
Please install the Tenable Host Doctor tool from https://github.com/ddangthatscrazy/tenable-host-doctor and set it up for use with the Claude skill. Here's what I need you to do:

1. Clone the repo and create a Python virtual environment
2. Install the package with API dependencies: pip install -e ".[api]"
3. Ask me for my Tenable API keys (TIO_ACCESS_KEY and TIO_SECRET_KEY) — I'll provide them and you should set them in the environment and write them to a .env file in the project directory so they persist
4. Install the skill by symlinking skill.md to ~/.claude/skills/host-doctor.md (Claude Code) or walk me through adding it via Settings → Capabilities → Skills (Claude Desktop)
5. Validate the installation by running: host-doctor --help
6. Validate the API connection by attempting to list my scans using the Tenable API
7. Confirm everything is working and tell me exactly how to invoke the skill

Do not skip the API key setup — prompt me for them even if I haven't mentioned them yet. If I don't have API keys, explain how to find them in Tenable under My Account → API Keys, and offer the manual .nessus export path as a fallback.
```

---

This guide is for users running Host Doctor alongside Claude (no LLM API key required). Claude acts as the AI layer — running the diagnostic analysis, interpreting the findings, connecting the dots, and giving you plain-language recommendations.

## Requirements

- Python 3.9+
- Claude desktop app (Cowork) **or** Claude Code CLI
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

The Host Doctor skill enables Claude to run the diagnostic analysis directly. Choose the instructions for your Claude environment.

### Claude Desktop (Cowork)

1. Open the Claude desktop app
2. Go to **Settings → Capabilities → Skills**
3. Click **Add Skill** and select the `skill.md` file from the cloned repo
4. Restart Claude if prompted

The skill will appear as `host-doctor` in your Claude conversations.

### Claude Code (CLI)

```bash
# Install globally (available in all projects)
mkdir -p ~/.claude/skills

# Symlink (recommended — picks up updates automatically)
ln -s "$(pwd)/skill.md" ~/.claude/skills/host-doctor.md

# Or copy it
cp skill.md ~/.claude/skills/host-doctor.md
```

Restart Claude Code if it's already running. The skill will be available as `/host-doctor`.

## Step 3 — Configure Tenable API Access

Install the API dependencies and set your Tenable credentials. This is required for Claude to fetch scans directly and use the automatic debug loop.

```bash
pip install -e ".[api]"
```

Then set your API keys in your terminal (you can find these in Tenable under **My Account → API Keys**):

```bash
export TIO_ACCESS_KEY="your-access-key"
export TIO_SECRET_KEY="your-secret-key"
```

To persist these across sessions, add both lines to your `~/.zshrc` or `~/.bashrc`.

> **Don't have API keys?** You can still use Host Doctor by exporting scans manually from the Tenable UI (Export → Nessus). Skip to Step 4, Option B. Note that `--auto-debug` will not be available.

## Step 4 — Get the scan data

**Option A: Export manually from Tenable UI**
1. Open your scan in Tenable.io
2. Click **Export** → **Nessus**
3. Download the `.nessus` file

**Option B: Let Claude fetch it (requires API credentials from Step 3)**
- Claude can download the scan using the Tenable API when you provide a scan name or ID

> **Tip:** The host identifier must match exactly how it appears in the scan — usually the IP address.

## Step 5 — Run the analysis in Claude

In the Claude desktop app, start a conversation and invoke the Host Doctor skill. Provide the scan file and the host you want to analyze:

> `/host-doctor analyze host 192.168.1.100 from my-scan.nessus`

Or if you uploaded the scan file:

> `/host-doctor` (then describe) "Analyze host 192.168.1.100 from the scan file I just shared"

### What Claude Does

When you invoke the skill, Claude will:
1. Parse the `.nessus` file
2. Run all diagnostic analyzers (authentication, network, policy, coverage)
3. Interpret the findings and connect the dots
4. Give you a plain-language explanation with prioritized recommendations
5. Generate a detailed report if requested

You'll get:
- A plain-language explanation of what's wrong
- Prioritized recommendations for what to fix first
- Specific remediation steps tailored to your environment
- Connections between findings (e.g., "auth succeeded but UAC is blocking registry access")

## Step 6 — If debug data is missing

If Claude tells you that plugin debugging wasn't enabled in the scan, you have two options:

**Option 1: Continue with available data**
The analysis will still identify most issues, but won't have detailed error messages or SSH command traces.

**Option 2: Enable debugging and re-scan**
Claude will walk you through:
1. Enabling "Plugin debugging" in your Tenable scan policy
2. Re-running the scan (ideally targeting just that one host)
3. Exporting the new `.nessus` file
4. Bringing it back for a deeper analysis

If you have API credentials configured, Claude can update the scan policy and trigger the re-scan automatically.

## Common Questions

**Do I need an API key for Claude?**
No. The skill runs inside the Claude desktop app using your existing Claude account.

**What if I don't have Tenable API credentials?**
Export the `.nessus` file manually from the Tenable UI (Export → Nessus) and share it with Claude. All analysis features work without API credentials — you just can't auto-fetch scans or auto-enable debugging.

**Do I need to run the host-doctor CLI command myself?**
No! That's the whole point of the Claude skill. Just invoke `/host-doctor` in Claude and describe what you want. Claude will run the analysis for you.

**Can Claude generate a report file?**
Yes. After the analysis, you can ask Claude to "generate an HTML report" or "save this as a JSON file" and it will create the report file for you.

**How do I know what host identifier to use?**
If you're not sure, just provide the scan file to Claude and ask "what hosts are in this scan?" Claude will list them for you.

## Example Conversation Flow

```
You: /host-doctor analyze host 192.168.1.100 from prod-scan.nessus

Claude: [Parses scan, runs analyzers]

I found 3 key issues preventing credentialed scanning on 192.168.1.100:

1. **Authentication Failed** - SSH credentials were rejected
   - Plugin 104410 shows: "Permission denied (publickey,password)"
   - The username 'scanner' is configured but authentication failed

2. **Missing Critical Plugin Families**
   - 0 local security check plugins ran (expected ~2000 for Ubuntu)
   - This confirms the authentication failure blocked all local checks

3. **Port 22 is open but timing out after auth attempt**
   - Suggests the SSH service may be rate-limiting or blocking after failed auth

**Recommended fix:** 
1. Verify the SSH credentials are correct for this host
2. Check if the 'scanner' user exists and has the right password/key
3. Review /var/log/auth.log on the host for specific SSH rejection reasons

Would you like me to generate a detailed HTML report?
```

## Further Reading

- `README.md` — full documentation and architecture
- `QUICKSTART.md` — CLI-first quickstart for users with their own LLM API key
- `skill.md` — the skill definition Claude uses to run the analysis
