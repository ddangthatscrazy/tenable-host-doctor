# LLM Integration for Host Doctor

## Architecture

The Host Doctor uses a **hybrid diagnostic approach** that combines deterministic analyzers with optional LLM enhancement:

```
┌─────────────────────────────────────────────────────────┐
│                  Diagnostic Flow                        │
└─────────────────────────────────────────────────────────┘
                          │
                          ▼
    ┌──────────────────────────────────────────┐
    │  1. Deterministic Analyzers (Fast Core)  │
    │     - auth.py: Cross-plugin correlation  │
    │     - network.py: Connectivity patterns  │
    │     - policy.py: Config validation       │
    │     - coverage.py: Plugin family checks  │
    └──────────────────────────────────────────┘
                          │
                          ▼ Findings with evidence
                          │
    ┌──────────────────────────────────────────┐
    │  2. LLM Enhancement (Optional Layer)     │
    │     - Root cause narratives              │
    │     - Plugin output interpretation       │
    │     - Cross-finding synthesis            │
    └──────────────────────────────────────────┘
                          │
                          ▼ Enriched findings
                          │
    ┌──────────────────────────────────────────┐
    │  3. Report Generation                    │
    │     - HTML/Markdown/JSON formats         │
    │     - Includes LLM narratives if present │
    └──────────────────────────────────────────┘
```

## Key Design Principles

### 1. Deterministic Backbone
The core findings always come from programmatic analyzers:
- Fast (no API latency)
- Auditable (explicit logic in code)
- Correct (tested patterns, no hallucination)
- Works offline (no API key required)

### 2. LLM as Narrator
The LLM adds context but doesn't drive findings:
- Explains *why* issues occurred, not just *what*
- Extracts root cause details from plugin outputs
- Synthesizes relationships between findings
- Gracefully absent if LLM unavailable/fails

### 3. Graceful Degradation
If you run Host Doctor with:
- **No API key**: Deterministic findings only
- **Weak model**: Less nuanced narratives, core findings intact
- **API failure**: Falls back to deterministic mode silently

## Implementation Details

### Finding Model
```python
@dataclass
class Finding:
    category: FindingCategory
    severity: Severity
    title: str
    description: str
    evidence: list[str]
    remediation: list[str]
    plugin_ids: list[int]
    
    # LLM enhancement (optional)
    llm_narrative: Optional[str] = None
```

### Agent Flow
```python
def _extract_findings_from_conversation(self) -> list[Finding]:
    # Step 1: Always run deterministic analyzers
    findings = self._run_deterministic_analyzers()
    
    # Step 2: If LLM participated, enhance findings
    if self.messages:
        findings = self._enhance_findings_with_llm_reasoning(findings)
    
    return findings
```

### Enhancement Process
1. **Run deterministic analyzers** → Get structured findings
2. **Request LLM narrative** → Ask for root cause explanations
3. **Match insights to findings** → Link narratives by plugin IDs
4. **Enrich finding objects** → Add `llm_narrative` field

## Report Output

Reports include LLM narratives when available:

**Markdown:**
```markdown
### 1. 🔴 [CRITICAL] SSH Authentication Failure

**Category:** authentication

SSH credentials failed to authenticate.

**Root Cause Analysis:**

> The SSH authentication failed because the private key has incorrect 
> permissions (644). Plugin 104410 shows 'Permissions 0644 for id_rsa 
> are too open', which violates OpenSSH security requirements.

**Evidence:**
- Plugin 104410 detected failure
```

**HTML:** Styled callout box with blue left border
**JSON:** `llm_narrative` field in each finding object

## Testing

Run the integration test:
```bash
python3 test_llm_integration.py
```

Tests verify:
1. Deterministic analyzers work without LLM
2. LLM enhancement structure matches insights correctly
3. Findings degrade gracefully when LLM unavailable

## Future Enhancements

Potential improvements:
- [ ] Semantic matching for insights (vs simple plugin ID matching)
- [ ] Executive summary finding that synthesizes all issues
- [ ] Extract specific error messages from plugin outputs
- [ ] Confidence scores for LLM narratives
- [ ] Multi-turn refinement if narrative unclear
