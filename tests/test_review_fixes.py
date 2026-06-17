"""Tests for the review-pass fixes: network plugin semantics, parser output
merging, HTML report escaping, and agent model wiring."""

import os
from datetime import datetime

from host_doctor.analyzers.network import analyze_network
from host_doctor.parsers.nessus import _merge_plugins
from host_doctor.models import (
    DiagnosticReport,
    HostData,
    Plugin,
    ScanConfig,
    Vulnerability,
)


# --- P1: 10114/10180 presence is reachability, not a timeout ------------------

def test_discovery_plugins_do_not_produce_timeout_finding():
    host = HostData(
        host_ip="10.0.0.1", operating_system="Linux", is_reachable=True,
        plugins={
            10180: Plugin(10180, "Ping the remote host", "Port scanners", 0,
                          plugin_output="The remote host is up."),
            10114: Plugin(10114, "ICMP Timestamp", "General", 0, plugin_output="ts"),
        },
        vulnerabilities=[Vulnerability(10180, "ping", "Port scanners", 0, port=0)],
    )
    findings = analyze_network(host, ScanConfig())
    titles = [f.title for f in findings]
    assert "Network Timeout Detected" not in titles


# --- P2: parser merges repeated plugin outputs instead of overwriting ---------

def test_merge_plugins_concatenates_distinct_outputs():
    a = Plugin(104410, "Cred Failure", "Settings", 0, plugin_output="Protocol : SSH\nport 22 failed")
    b = Plugin(104410, "Cred Failure", "Settings", 0, plugin_output="Protocol : SMB\nport 445 failed")
    merged = _merge_plugins(a, b)
    assert "SSH" in merged.plugin_output
    assert "SMB" in merged.plugin_output


def test_merge_plugins_dedupes_identical_output():
    a = Plugin(21745, "LC", "Settings", 0, plugin_output="same body")
    b = Plugin(21745, "LC", "Settings", 0, plugin_output="same body")
    merged = _merge_plugins(a, b)
    assert merged.plugin_output == "same body"


def test_merge_plugins_keeps_metadata_from_output_bearing_record():
    a = Plugin(104410, "Cred Failure", "Settings", 2, plugin_output=None)
    b = Plugin(104410, "Cred Failure", "Settings", 0, plugin_output="Protocol : SSH")
    merged = _merge_plugins(a, b)
    assert merged.plugin_output == "Protocol : SSH"
    assert merged.severity == 2  # max of the two


# --- P2: HTML report escapes metadata fields ----------------------------------

def test_html_report_escapes_scan_name(tmp_path):
    from host_doctor.report import generate_report
    report = DiagnosticReport(
        host_ip="10.0.0.1",
        scan_name="<script>alert('x')</script>",
        generated_at=datetime.now(),
        nessus_file="scan.nessus",
        findings=[],
    )
    out = tmp_path / "r.html"
    generate_report(report, out, format="html")
    html = out.read_text(encoding="utf-8")
    assert "<script>alert" not in html
    assert "&lt;script&gt;" in html


# --- P2: agent honors SCAN_DOCTOR_MODEL and gates the LLM loop -----------------

def test_agent_uses_configured_model(monkeypatch):
    # Re-import config so the env var is picked up freshly.
    monkeypatch.setenv("SCAN_DOCTOR_MODEL", "ollama/llama3.1")
    import importlib
    import host_doctor.config as cfg
    importlib.reload(cfg)
    from host_doctor.agent.agent import DiagnosticAgent

    agent = DiagnosticAgent(
        host_data=HostData(host_ip="10.0.0.1"),
        scan_config=ScanConfig(),
        model=cfg.config.SCAN_DOCTOR_MODEL,
    )
    assert agent.model == "ollama/llama3.1"


def test_agent_llm_disabled_without_provider_key(monkeypatch):
    # No provider key + a non-ollama model -> llm disabled -> deterministic only.
    monkeypatch.setenv("SCAN_DOCTOR_MODEL", "anthropic/claude-sonnet-4-6")
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    import importlib
    import host_doctor.config as cfg
    importlib.reload(cfg)
    from host_doctor.agent.agent import DiagnosticAgent

    agent = DiagnosticAgent(
        host_data=HostData(host_ip="10.0.0.1"),
        scan_config=ScanConfig(),
        model=cfg.config.SCAN_DOCTOR_MODEL,
    )
    assert agent.llm_enabled is False
