# Architecture

## Design Philosophy

**Local-first, deterministic analysis** - No iterative LLM loop, no heavy API usage.

```
Input → Parse → Analyze → Report
 ↓        ↓        ↓        ↓
.nessus  Host    Checks   HTML
.db      Data    (30+)    
.kb      Config
```

## Data Flow

```
┌─────────────────┐
│  Input Files    │
│  - .nessus      │  Parse once, analyze many times
│  - nessus.db    │  
│  - .kb          │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│   Parsers       │
│  - XMLParser    │  Extract structured data
│  - SQLReader    │
│  - KBParser     │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  Data Models    │
│  - HostData     │  Type-safe, validated
│  - ScanConfig   │
│  - Finding      │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│   Analyzers     │
│  auth.py        │  Each returns list[Finding]
│  network.py     │  Independent, composable
│  policy.py      │
│  ...            │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ DiagnosticReport│  Aggregate all findings
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  Report Gen     │
│  - HTML         │  Styled, self-contained
│  - Markdown     │
│  - JSON         │
└─────────────────┘
```

## Module Responsibilities

### parsers/
**Input → Structured Data**

- `nessus.py`: XML → HostData + ScanConfig
- `nessusdb.py`: SQLite queries for host/plugin data
- `kb.py`: Binary KB → historical state dict

### analyzers/
**Structured Data → Findings**

Each analyzer:
1. Takes `HostData` + `ScanConfig`
2. Runs deterministic checks
3. Returns `list[Finding]`

**Principle:** Single responsibility, no side effects, easy to test

- `config.py`: Extract scan configuration from plugin 19506
- `auth.py`: Authentication issues (credentials, protocols)
- `network.py`: Connectivity, timeouts, MTU
- `policy.py`: Plugin families, safe checks, version staleness
- `performance.py`: Duration anomalies, resource exhaustion
- `historical.py`: Compare with .kb baseline

### models.py
**Type System**

- `HostData`: Complete host scan results
- `ScanConfig`: Extracted configuration
- `Finding`: Single diagnostic issue
- `DiagnosticReport`: Aggregated findings + metadata

### report.py
**Findings → User-Facing Output**

- HTML: Self-contained, styled, collapsible sections
- Markdown: For tickets/documentation
- JSON: For automation/integration

### scan_creator.py
**Generate Diagnostic Scan Configs**

When host lacks diagnostic data:
1. Base config from current scan
2. Enable diagnostic plugins (19506, 84239, etc.)
3. Set verbose logging
4. Extend timeouts
5. Output JSON for import to Tenable

## Analyzer Pattern

```python
def analyze_authentication(
    host_data: HostData, 
    scan_config: ScanConfig
) -> list[Finding]:
    """Check for authentication issues."""
    
    findings = []
    
    # Check 1: Credential type mismatch
    if _credential_type_mismatch(host_data, scan_config):
        findings.append(Finding(
            category=FindingCategory.AUTHENTICATION,
            severity=Severity.CRITICAL,
            title="Credential Type Mismatch",
            description="...",
            evidence=["...", "..."],
            remediation=["...", "..."],
            plugin_ids=[104410, 141118],
        ))
    
    # Check 2: Protocol failures
    # ...
    
    return findings
```

**Benefits:**
- Easy to add new checks (just append to findings)
- Easy to test (pure function, no state)
- Easy to disable (comment out analyzer)
- Parallelizable (if needed in future)

## Extension Points

### Add New Analyzer

1. Create `analyzers/new_check.py`
2. Implement: `def analyze_xxx(host_data, scan_config) -> list[Finding]`
3. Register in `analyzers/__init__.py`
4. Import in `cli.py` and add to analysis loop

### Add New Parser

1. Create `parsers/new_format.py`
2. Implement: `def parse_xxx(path: Path) -> dict[str, Any]`
3. Merge into `HostData` or `ScanConfig`

### Add New Report Format

1. Add generator in `report.py`
2. Add format option to CLI
3. Register template (if template-based)

## Performance Characteristics

| Operation | Time (100-host scan) |
|-----------|---------------------|
| Parse .nessus XML | ~2s |
| Parse nessus.db | ~0.5s |
| Run all analyzers | ~0.1s |
| Generate HTML report | ~0.2s |
| **Total** | **~3s** |

**vs. API mode:** 100+ API calls = 20-30s + rate limit risk

## Testing Strategy

### Unit Tests
- Each analyzer independently
- Mock HostData/ScanConfig inputs
- Assert expected findings

### Integration Tests
- Real .nessus files (sanitized/anonymized)
- End-to-end: parse → analyze → report
- Regression: known issues should be detected

### Test Data
```
tests/
├── fixtures/
│   ├── auth_failure.nessus
│   ├── timeout_issue.nessus
│   ├── policy_mismatch.nessus
│   └── clean_scan.nessus
└── test_*.py
```

## Error Handling

**Fail gracefully:**
- Missing plugin output? Skip check, note in report
- Corrupt .nessus? Parse what's possible, warn user
- No diagnostic data? Suggest creating diagnostic scan

**Never fail silently** - always surface issues to user

## Future: Plugin System

```python
# user_plugins/custom_check.py

@register_analyzer
def check_custom_requirement(host_data, scan_config):
    """Custom company-specific check."""
    ...
    return findings
```

Auto-discovered and executed with built-in analyzers.
