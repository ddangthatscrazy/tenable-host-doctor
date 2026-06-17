"""Stub implementations for report generation."""

from pathlib import Path

from host_doctor.models import DiagnosticReport


def generate_report(report: DiagnosticReport, output_path: Path, format: str) -> None:
    """Generate a diagnostic report in the specified format.

    Args:
        report: DiagnosticReport with findings
        output_path: Path to write report to
        format: 'html', 'markdown', or 'json'
    """
    if format == "html":
        _generate_html_report(report, output_path)
    elif format == "markdown":
        _generate_markdown_report(report, output_path)
    elif format == "json":
        _generate_json_report(report, output_path)
    else:
        raise ValueError(f"Unknown report format: {format}")


def _generate_html_report(report: DiagnosticReport, output_path: Path) -> None:
    """Generate professional HTML report with consistent styling."""
    # Group findings by category for better organization
    findings_by_category = {}
    executive_summary = None

    for finding in report.findings:
        if finding.title == "Executive Summary":
            executive_summary = finding
        else:
            category = finding.category.value
            if category not in findings_by_category:
                findings_by_category[category] = []
            findings_by_category[category].append(finding)

    # Sort categories by severity (most severe first)
    category_severity = {}
    for cat, findings in findings_by_category.items():
        max_sev = max((f.severity.value for f in findings), default="info")
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        category_severity[cat] = severity_order.get(max_sev, 5)

    sorted_categories = sorted(findings_by_category.keys(), key=lambda c: category_severity[c])

    # Build HTML
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Tenable Host Doctor Report - {_escape_html(str(report.host_ip))}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: #333;
            background: #f5f5f5;
            padding: 20px;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            border-radius: 8px;
            overflow: hidden;
        }}
        .header {{
            background: linear-gradient(135deg, #00a8e1 0%, #0073aa 100%);
            color: white;
            padding: 40px;
        }}
        .header h1 {{ font-size: 2.5em; margin-bottom: 10px; font-weight: 600; }}
        .header .subtitle {{ font-size: 1.2em; opacity: 0.9; }}
        .header .meta {{ margin-top: 15px; font-size: 0.95em; opacity: 0.85; }}

        .content {{ padding: 40px; }}

        .summary-box {{
            background: linear-gradient(135deg, #f0f9ff 0%, #e0f2fe 100%);
            border-left: 4px solid #00a8e1;
            padding: 25px;
            margin: 30px 0;
            border-radius: 4px;
        }}
        .summary-box h2 {{
            color: #0073aa;
            margin-bottom: 15px;
            font-size: 1.5em;
        }}

        .severity-badges {{
            display: flex;
            gap: 15px;
            flex-wrap: wrap;
            margin: 20px 0;
        }}
        .badge {{
            display: inline-flex;
            align-items: center;
            padding: 10px 20px;
            border-radius: 6px;
            font-size: 0.95em;
            font-weight: 600;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        .badge-critical {{ background: #dc2626; color: white; }}
        .badge-high {{ background: #ea580c; color: white; }}
        .badge-medium {{ background: #f59e0b; color: white; }}
        .badge-low {{ background: #3b82f6; color: white; }}
        .badge-info {{ background: #64748b; color: white; }}
        .badge .count {{
            font-size: 1.8em;
            font-weight: 700;
            margin-right: 8px;
        }}

        .section {{
            margin: 40px 0;
        }}
        .section-title {{
            font-size: 1.8em;
            margin-bottom: 20px;
            padding-bottom: 10px;
            border-bottom: 2px solid #e5e7eb;
            color: #1f2937;
            font-weight: 600;
        }}

        .category-section {{
            margin: 30px 0;
        }}
        .category-header {{
            background: #f9fafb;
            padding: 15px 20px;
            border-left: 4px solid #9ca3af;
            margin-bottom: 20px;
            border-radius: 4px;
        }}
        .category-header h3 {{
            color: #374151;
            font-size: 1.3em;
            text-transform: capitalize;
        }}

        .finding {{
            background: #ffffff;
            border: 1px solid #e5e7eb;
            border-radius: 8px;
            padding: 25px;
            margin: 20px 0;
            box-shadow: 0 1px 3px rgba(0,0,0,0.05);
            transition: box-shadow 0.2s;
        }}
        .finding:hover {{
            box-shadow: 0 4px 12px rgba(0,0,0,0.1);
        }}
        .finding.critical {{ border-left: 5px solid #dc2626; }}
        .finding.high {{ border-left: 5px solid #ea580c; }}
        .finding.medium {{ border-left: 5px solid #f59e0b; }}
        .finding.low {{ border-left: 5px solid #3b82f6; }}
        .finding.info {{ border-left: 5px solid #64748b; }}

        .finding-header {{
            display: flex;
            align-items: flex-start;
            margin-bottom: 15px;
        }}
        .finding-icon {{
            font-size: 2em;
            margin-right: 15px;
            line-height: 1;
        }}
        .finding-title-block {{
            flex: 1;
        }}
        .finding-title {{
            font-size: 1.3em;
            font-weight: 600;
            color: #1f2937;
            margin-bottom: 5px;
        }}
        .finding-severity {{
            display: inline-block;
            padding: 3px 10px;
            border-radius: 3px;
            font-size: 0.75em;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }}
        .severity-critical {{ background: #fecaca; color: #991b1b; }}
        .severity-high {{ background: #fed7aa; color: #9a3412; }}
        .severity-medium {{ background: #fef3c7; color: #92400e; }}
        .severity-low {{ background: #bfdbfe; color: #1e3a8a; }}
        .severity-info {{ background: #e2e8f0; color: #334155; }}

        .finding-body {{
            margin-top: 15px;
            color: #4b5563;
        }}
        .finding-body p {{
            margin: 10px 0;
            line-height: 1.7;
        }}

        .subsection {{
            margin: 20px 0;
        }}
        .subsection-title {{
            font-weight: 600;
            color: #374151;
            margin-bottom: 10px;
            font-size: 1.05em;
        }}

        .llm-analysis {{
            background: linear-gradient(135deg, #eff6ff 0%, #dbeafe 100%);
            border-left: 4px solid #2563eb;
            padding: 20px;
            border-radius: 4px;
            margin: 20px 0;
        }}
        .llm-analysis h4 {{
            color: #1e40af;
            margin-bottom: 10px;
            font-size: 1.1em;
        }}
        .llm-analysis p {{
            color: #1e3a8a;
            line-height: 1.8;
        }}

        .evidence-list, .remediation-list {{
            margin: 10px 0 10px 20px;
        }}
        .evidence-list li {{
            margin: 8px 0;
            color: #4b5563;
            line-height: 1.6;
        }}
        .remediation-list li {{
            margin: 12px 0;
            color: #374151;
            line-height: 1.7;
        }}

        .plugin-refs {{
            margin-top: 15px;
            padding: 12px;
            background: #f9fafb;
            border-radius: 4px;
            font-size: 0.9em;
            color: #6b7280;
        }}

        .footer {{
            margin-top: 40px;
            padding: 30px 40px;
            background: #f9fafb;
            border-top: 1px solid #e5e7eb;
            text-align: center;
            color: #6b7280;
            font-size: 0.9em;
        }}

        @media print {{
            body {{ background: white; padding: 0; }}
            .container {{ box-shadow: none; }}
            .finding {{ break-inside: avoid; }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔬 Tenable Host Doctor Report</h1>
            <div class="subtitle">Diagnostic Analysis for {_escape_html(str(report.host_ip))}</div>
            <div class="meta">
                <div>Scan: {_escape_html(str(report.scan_name))}</div>
                <div>Generated: {report.generated_at.strftime("%Y-%m-%d %H:%M:%S")}</div>
                <div>Source: {_escape_html(str(report.nessus_file))}</div>
            </div>
        </div>

        <div class="content">
            <div class="summary-box">
                <h2>📊 Findings Summary</h2>
                <div class="severity-badges">
                    {f'<div class="badge badge-critical"><span class="count">{report.critical_count}</span> Critical</div>' if report.critical_count > 0 else ''}
                    {f'<div class="badge badge-high"><span class="count">{report.high_count}</span> High</div>' if report.high_count > 0 else ''}
                    {f'<div class="badge badge-medium"><span class="count">{report.medium_count}</span> Medium</div>' if report.medium_count > 0 else ''}
                    {f'<div class="badge badge-low"><span class="count">{report.low_count}</span> Low</div>' if report.low_count > 0 else ''}
                    {f'<div class="badge badge-info"><span class="count">{report.info_count}</span> Info</div>' if report.info_count > 0 else ''}
                </div>
                {f'<p style="margin-top: 15px; color: #374151;"><strong>Total Issues:</strong> {len(report.findings)} findings across {len(findings_by_category)} categories</p>' if findings_by_category else ''}
            </div>"""

    # Add executive summary if present
    if executive_summary and executive_summary.llm_narrative:
        html += f"""
            <div class="section">
                <h2 class="section-title">📋 Executive Summary</h2>
                <div class="llm-analysis">
                    <p>{_escape_html(executive_summary.llm_narrative)}</p>
                </div>
            </div>"""

    # Add findings by category
    if findings_by_category:
        html += """
            <div class="section">
                <h2 class="section-title">🔍 Detailed Findings</h2>"""

        for category in sorted_categories:
            findings = findings_by_category[category]
            category_icon = {
                "authentication": "🔐",
                "network": "🌐",
                "configuration": "⚙️",
                "policy": "📜",
                "performance": "⚡",
                "missing_diagnostics": "🔧"
            }.get(category, "📌")

            html += f"""
                <div class="category-section">
                    <div class="category-header">
                        <h3>{category_icon} {category.replace('_', ' ').title()}</h3>
                    </div>"""

            for finding in findings:
                severity_class = finding.severity.value
                severity_icon = {
                    "critical": "🔴",
                    "high": "🟠",
                    "medium": "🟡",
                    "low": "🔵",
                    "info": "⚪"
                }.get(severity_class, "⚪")

                html += f"""
                    <div class="finding {severity_class}">
                        <div class="finding-header">
                            <div class="finding-icon">{severity_icon}</div>
                            <div class="finding-title-block">
                                <div class="finding-title">{_escape_html(finding.title)}</div>
                                <span class="finding-severity severity-{severity_class}">{severity_class}</span>
                            </div>
                        </div>
                        <div class="finding-body">
                            <p>{_escape_html(finding.description)}</p>"""

                if finding.llm_narrative:
                    html += f"""
                            <div class="llm-analysis">
                                <h4>🧠 Root Cause Analysis</h4>
                                <p>{_escape_html(finding.llm_narrative)}</p>
                            </div>"""

                if finding.evidence:
                    html += """
                            <div class="subsection">
                                <div class="subsection-title">📎 Evidence</div>
                                <ul class="evidence-list">"""
                    for evidence_item in finding.evidence:
                        html += f"<li>{_escape_html(evidence_item)}</li>"
                    html += """
                                </ul>
                            </div>"""

                if finding.remediation:
                    html += """
                            <div class="subsection">
                                <div class="subsection-title">✅ Remediation Steps</div>
                                <ol class="remediation-list">"""
                    for step in finding.remediation:
                        html += f"<li>{_escape_html(step)}</li>"
                    html += """
                                </ol>
                            </div>"""

                if finding.plugin_ids:
                    plugin_list = ", ".join(str(pid) for pid in finding.plugin_ids)
                    html += f"""
                            <div class="plugin-refs">
                                <strong>Related Plugins:</strong> {plugin_list}
                            </div>"""

                html += """
                        </div>
                    </div>"""

            html += """
                </div>"""

        html += """
            </div>"""
    else:
        html += """
            <div class="section">
                <div class="summary-box">
                    <h2>✅ No Issues Found</h2>
                    <p>This host appears to be scanning correctly with no diagnostic issues detected.</p>
                </div>
            </div>"""

    html += f"""
        </div>

        <div class="footer">
            <div><strong>Tenable Host Doctor</strong> v0.1.0</div>
            <div>Diagnostic analysis for single-host scan issues</div>
            <div style="margin-top: 10px; font-size: 0.85em;">
                Generated on {report.generated_at.strftime("%Y-%m-%d at %H:%M:%S")}
            </div>
        </div>
    </div>
</body>
</html>"""

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)


def _escape_html(text: str) -> str:
    """Escape HTML special characters."""
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&#x27;")
    )


def _generate_markdown_report(report: DiagnosticReport, output_path: Path) -> None:
    """Generate Markdown report with consistent structure."""
    # Group findings by category
    findings_by_category = {}
    executive_summary = None

    for finding in report.findings:
        if finding.title == "Executive Summary":
            executive_summary = finding
        else:
            category = finding.category.value
            if category not in findings_by_category:
                findings_by_category[category] = []
            findings_by_category[category].append(finding)

    # Sort categories by severity
    category_severity = {}
    for cat, findings in findings_by_category.items():
        max_sev = max((f.severity.value for f in findings), default="info")
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        category_severity[cat] = severity_order.get(max_sev, 5)

    sorted_categories = sorted(findings_by_category.keys(), key=lambda c: category_severity[c])

    md = f"""# 🔬 Tenable Host Doctor Report

**Host:** {report.host_ip}
**Scan:** {report.scan_name}
**Generated:** {report.generated_at.strftime("%Y-%m-%d %H:%M:%S")}
**Data Source:** {report.nessus_file}

---

## 📊 Findings Summary

| Severity | Count |
|----------|-------|
| 🔴 Critical | {report.critical_count} |
| 🟠 High | {report.high_count} |
| 🟡 Medium | {report.medium_count} |
| 🔵 Low | {report.low_count} |
| ⚪ Info | {report.info_count} |

**Total Issues:** {len(report.findings)} findings across {len(findings_by_category)} categories

---

"""

    # Add executive summary if present
    if executive_summary and executive_summary.llm_narrative:
        md += f"""## 📋 Executive Summary

> {executive_summary.llm_narrative}

---

"""

    # Add findings by category
    if findings_by_category:
        md += """## 🔍 Detailed Findings

"""
        for category in sorted_categories:
            findings = findings_by_category[category]
            category_icon = {
                "authentication": "🔐",
                "network": "🌐",
                "configuration": "⚙️",
                "policy": "📜",
                "performance": "⚡",
                "missing_diagnostics": "🔧"
            }.get(category, "📌")

            md += f"""### {category_icon} {category.replace('_', ' ').title()}

"""

            for i, finding in enumerate(findings, 1):
                severity_emoji = {
                    "critical": "🔴",
                    "high": "🟠",
                    "medium": "🟡",
                    "low": "🔵",
                    "info": "⚪",
                }.get(finding.severity.value, "⚪")

                md += f"""#### {i}. {severity_emoji} {finding.title}

**Severity:** {finding.severity.value.upper()}

{finding.description}

"""

                if finding.llm_narrative:
                    md += f"""**🧠 Root Cause Analysis:**

> {finding.llm_narrative}

"""

                if finding.evidence:
                    md += """**📎 Evidence:**

"""
                    for evidence_item in finding.evidence:
                        md += f"- {evidence_item}\n"
                    md += "\n"

                if finding.remediation:
                    md += """**✅ Remediation Steps:**

"""
                    for j, step in enumerate(finding.remediation, 1):
                        md += f"{j}. {step}\n"
                    md += "\n"

                if finding.plugin_ids:
                    plugin_list = ", ".join(str(pid) for pid in finding.plugin_ids)
                    md += f"""**Related Plugins:** {plugin_list}

"""

                md += "---\n\n"
    else:
        md += """## ✅ No Issues Found

This host appears to be scanning correctly with no diagnostic issues detected.

"""

    md += f"""---

*Generated by Tenable Host Doctor v0.1.0 on {report.generated_at.strftime("%Y-%m-%d at %H:%M:%S")}*
"""

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(md)


def _generate_json_report(report: DiagnosticReport, output_path: Path) -> None:
    """Generate structured JSON report."""
    import json

    # Group findings by category
    findings_by_category = {}
    executive_summary = None

    for finding in report.findings:
        if finding.title == "Executive Summary":
            executive_summary = finding
        else:
            category = finding.category.value
            if category not in findings_by_category:
                findings_by_category[category] = []
            findings_by_category[category].append({
                "severity": finding.severity.value,
                "title": finding.title,
                "description": finding.description,
                "evidence": finding.evidence,
                "remediation": finding.remediation,
                "plugin_ids": finding.plugin_ids,
                "llm_narrative": finding.llm_narrative,
            })

    data = {
        "report_metadata": {
            "host_ip": report.host_ip,
            "scan_name": report.scan_name,
            "generated_at": report.generated_at.isoformat(),
            "nessus_file": report.nessus_file,
            "nessus_db_used": report.nessus_db_used,
            "kb_file_used": report.kb_file_used,
        },
        "summary": {
            "total_findings": len(report.findings),
            "by_severity": {
                "critical": report.critical_count,
                "high": report.high_count,
                "medium": report.medium_count,
                "low": report.low_count,
                "info": report.info_count,
            },
            "categories": list(findings_by_category.keys()),
        },
        "executive_summary": (
            executive_summary.llm_narrative if executive_summary and executive_summary.llm_narrative else None
        ),
        "findings_by_category": findings_by_category,
        "needs_diagnostic_scan": report.needs_diagnostic_scan,
    }

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
