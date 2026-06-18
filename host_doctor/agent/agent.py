"""AI agent loop for diagnostic reasoning."""

from dataclasses import dataclass
from typing import Any, Callable, Optional

from host_doctor.models import DiagnosticReport, Finding, FindingCategory, HostData, ScanConfig, Severity


@dataclass
class ToolResult:
    """Result from a tool execution."""

    success: bool
    data: Any
    error: Optional[str] = None


class DiagnosticAgent:
    """AI agent that reasons about host scan issues and calls diagnostic tools.

    This maintains the iterative investigation style from Scan Doctor,
    but uses local file data instead of API calls.
    """

    def __init__(
        self,
        host_data: HostData,
        scan_config: ScanConfig,
        model: Optional[str] = None,
        verbose: bool = False,
    ):
        """Initialize diagnostic agent.

        Args:
            host_data: Parsed host scan data
            scan_config: Parsed scan configuration
            model: LiteLLM model string. If None, falls back to
                config.SCAN_DOCTOR_MODEL (the single source of truth, set via the
                SCAN_DOCTOR_MODEL env var documented in the README).
            verbose: Print agent reasoning steps
        """
        from host_doctor.config import config

        self.host_data = host_data
        self.scan_config = scan_config
        self.model = model or config.SCAN_DOCTOR_MODEL
        # Only run the LLM reasoning loop when a provider is actually configured.
        # Otherwise we go straight to the deterministic analyzers (the documented
        # fallback) instead of attempting and failing an LLM call every iteration.
        self.llm_enabled = config.has_llm_config()
        self.verbose = verbose

        # Conversation history
        self.messages = []
        self.tool_calls = []

        # Available tools (all work on local data)
        self.tools = self._register_tools()

    def _register_tools(self) -> dict[str, Callable]:
        """Register all available diagnostic tools.

        Tools operate on local data (host_data, scan_config) only.
        No API calls.
        """
        from host_doctor.agent.tools import (
            check_authentication_status,
            check_network_connectivity,
            check_plugin_coverage,
            check_scan_timing,
            get_plugin_output,
            get_scan_configuration,
            list_failed_plugins,
            list_vulnerabilities_by_family,
            compare_with_expected_results,
            analyze_credential_configuration,
            check_for_timeout_patterns,
            detect_firewall_blocking,
        )

        return {
            "get_scan_configuration": get_scan_configuration,
            "check_authentication_status": check_authentication_status,
            "get_plugin_output": get_plugin_output,
            "list_failed_plugins": list_failed_plugins,
            "list_vulnerabilities_by_family": list_vulnerabilities_by_family,
            "check_network_connectivity": check_network_connectivity,
            "check_plugin_coverage": check_plugin_coverage,
            "check_scan_timing": check_scan_timing,
            "compare_with_expected_results": compare_with_expected_results,
            "analyze_credential_configuration": analyze_credential_configuration,
            "check_for_timeout_patterns": check_for_timeout_patterns,
            "detect_firewall_blocking": detect_firewall_blocking,
        }

    def run(self, max_iterations: int = 15) -> DiagnosticReport:
        """Run the agent's diagnostic loop.

        Agent will:
        1. Analyze current state
        2. Decide what to investigate next
        3. Call diagnostic tools
        4. Reason about results
        5. Repeat until confident in root cause or max iterations

        Args:
            max_iterations: Maximum reasoning loop iterations

        Returns:
            DiagnosticReport with findings and recommendations
        """
        # Initialize with system prompt
        system_prompt = self._get_system_prompt()
        self.messages.append({"role": "system", "content": system_prompt})

        # Initial user message
        initial_query = f"""Analyze host {self.host_data.host_ip} from scan "{self.scan_config.scan_name}".

Investigate why this host may have scan issues. Use the available tools to gather evidence,
then determine root causes and provide remediation recommendations.

Focus on:
1. Authentication failures
2. Network connectivity issues
3. Configuration mismatches
4. Plugin coverage gaps
5. Timing/timeout problems

Be thorough but efficient. When you have high confidence in root cause, generate findings."""

        self.messages.append({"role": "user", "content": initial_query})

        # Reasoning loop — only when an LLM provider is configured. Without one,
        # we skip straight to the deterministic analyzers below (messages stays at
        # system+user, so no LLM enhancement is attempted either).
        if not self.llm_enabled:
            if self.verbose:
                print("[Agent] No LLM provider configured; running deterministic analysis only.")
        else:
            for iteration in range(max_iterations):
                if self.verbose:
                    print(f"\n[Agent Iteration {iteration + 1}/{max_iterations}]")

                # Get LLM response with tool calls
                response = self._call_llm()

                # Extract tool calls (returns list of (name, args, tool_call_id))
                tool_calls = self._extract_tool_calls(response)

                if not tool_calls:
                    # Agent finished reasoning, extract findings
                    if self.verbose:
                        print("[Agent] Completed investigation")
                    break

                # Add the assistant's message (with tool_calls) to history BEFORE results
                try:
                    assistant_message = response["choices"][0]["message"]
                    self.messages.append(assistant_message)
                except (KeyError, IndexError):
                    pass

                # Execute tools
                tool_results = []
                for tool_name, args, tool_call_id in tool_calls:
                    if self.verbose:
                        print(f"  Tool: {tool_name}({args})")

                    result = self._execute_tool(tool_name, args)
                    tool_results.append((tool_name, result, tool_call_id))

                    if self.verbose and result.success:
                        print(f"    ✓ Success")
                    elif self.verbose:
                        print(f"    ✗ Error: {result.error}")

                # Add tool results to conversation (one message per call with tool_call_id)
                self._append_tool_results(tool_results)

        # Extract findings from final conversation
        findings = self._extract_findings_from_conversation()

        # Build diagnostic report
        from datetime import datetime

        needs_debug = any(
            f.category == FindingCategory.MISSING_DIAGNOSTICS
            and "Plugin Debugging" in f.title
            for f in findings
        )

        report = DiagnosticReport(
            host_ip=self.host_data.host_ip,
            scan_name=self.scan_config.scan_name or "Unknown",
            generated_at=datetime.now(),
            nessus_file="(loaded in memory)",
            findings=findings,
            host_data=self.host_data,
            scan_config=self.scan_config,
            needs_diagnostic_scan=needs_debug,
        )

        return report

    def _call_llm(self) -> dict[str, Any]:
        """Call LLM with current conversation and tool definitions."""
        try:
            import litellm

            response = litellm.completion(
                model=self.model,
                messages=self.messages,
                tools=self._get_tool_definitions(),
                tool_choice="auto",
            )

            return response

        except Exception as e:
            # Fallback: if LLM fails, run deterministic checks
            if self.verbose:
                print(f"[Agent] LLM call failed: {e}, falling back to deterministic mode")
            return {"choices": [{"message": {"content": "Using fallback mode"}}]}

    def _execute_tool(self, tool_name: str, args: dict[str, Any]) -> ToolResult:
        """Execute a diagnostic tool with given arguments."""
        if tool_name not in self.tools:
            return ToolResult(
                success=False, data=None, error=f"Unknown tool: {tool_name}"
            )

        try:
            tool_fn = self.tools[tool_name]

            # All tools receive host_data and scan_config
            result = tool_fn(
                host_data=self.host_data, scan_config=self.scan_config, **args
            )

            return ToolResult(success=True, data=result)

        except Exception as e:
            return ToolResult(success=False, data=None, error=str(e))

    def _get_system_prompt(self) -> str:
        """Get the agent's system prompt with diagnostic expertise."""
        return """You are a Tenable vulnerability scanning expert specializing in diagnosing why specific hosts fail to scan properly.

Your expertise includes:
- Nessus plugin behavior and output interpretation
- Windows/Linux/Unix authentication mechanisms (SSH, WMI, SNMP)
- Network connectivity and firewall issues
- Scan configuration and policy settings
- Timeout and performance problems

You have access to complete scan data for a single host (already parsed from .nessus file).
Use the available tools to investigate, but DO NOT make API calls - all data is local.

Investigation Strategy:
1. Start with high-level checks (scan config, auth status)
2. Drill into specifics based on initial findings
3. Look at plugin outputs for detailed error messages
4. Compare configuration vs actual results
5. Identify root cause with evidence
6. Provide actionable remediation steps

When you identify issues, describe them clearly:
- Severity (critical/high/medium/low/info)
- Category (authentication/network/configuration/policy)
- Evidence (specific plugin IDs and outputs)
- Root cause explanation
- Remediation steps

Be efficient - don't call tools unnecessarily if you already have the answer.
Be thorough - don't guess if you can check.
Be specific - cite plugin IDs and exact error messages."""

    def _get_tool_definitions(self) -> list[dict[str, Any]]:
        """Get OpenAI-format tool definitions for LLM."""
        # Tool definitions for LLM
        # Each tool operates on local data only
        return [
            {
                "type": "function",
                "function": {
                    "name": "get_scan_configuration",
                    "description": "Get scan configuration details (policy, scanner, timeouts, credentials configured, etc.)",
                    "parameters": {"type": "object", "properties": {}},
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "check_authentication_status",
                    "description": "Check authentication success/failure status for this host",
                    "parameters": {"type": "object", "properties": {}},
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "get_plugin_output",
                    "description": "Get raw plugin output text for a specific plugin ID",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "plugin_id": {
                                "type": "integer",
                                "description": "Plugin ID (e.g., 19506, 84239, 104410)",
                            }
                        },
                        "required": ["plugin_id"],
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "list_failed_plugins",
                    "description": "List plugins that reported errors or failures",
                    "parameters": {"type": "object", "properties": {}},
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "list_vulnerabilities_by_family",
                    "description": "List vulnerabilities by plugin family (e.g., 'Windows', 'Red Hat Local Security Checks')",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "family": {
                                "type": "string",
                                "description": "Plugin family name",
                            }
                        },
                        "required": ["family"],
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "check_network_connectivity",
                    "description": "Check for network connectivity issues (timeouts, unreachable, etc.)",
                    "parameters": {"type": "object", "properties": {}},
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "check_plugin_coverage",
                    "description": "Check if appropriate plugin families ran for detected OS",
                    "parameters": {"type": "object", "properties": {}},
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "check_scan_timing",
                    "description": "Analyze scan timing and duration for anomalies",
                    "parameters": {"type": "object", "properties": {}},
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "compare_with_expected_results",
                    "description": "Compare what should have happened vs what actually happened based on config",
                    "parameters": {"type": "object", "properties": {}},
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "analyze_credential_configuration",
                    "description": "Analyze credential configuration for mismatches (local vs domain, protocol mismatches)",
                    "parameters": {"type": "object", "properties": {}},
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "check_for_timeout_patterns",
                    "description": "Look for patterns indicating timeout issues",
                    "parameters": {"type": "object", "properties": {}},
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "detect_firewall_blocking",
                    "description": "Detect patterns suggesting firewall blocking",
                    "parameters": {"type": "object", "properties": {}},
                },
            },
        ]

    def _extract_tool_calls(self, response: dict[str, Any]) -> list[tuple[str, dict, str]]:
        """Extract tool calls from LLM response.

        Returns list of (tool_name, args, tool_call_id).
        """
        try:
            choice = response["choices"][0]
            message = choice["message"]

            if "tool_calls" in message:
                calls = []
                for tc in message["tool_calls"]:
                    tool_name = tc["function"]["name"]
                    args = tc["function"].get("arguments", {})
                    tool_call_id = tc.get("id", f"call_{tool_name}")

                    # Parse JSON string if needed
                    if isinstance(args, str):
                        import json
                        args = json.loads(args)

                    calls.append((tool_name, args, tool_call_id))
                return calls

        except Exception as e:
            if self.verbose:
                print(f"[Agent] Failed to extract tool calls: {e}")

        return []

    def _append_tool_results(self, results: list[tuple[str, ToolResult, str]]):
        """Append tool results to conversation.

        One message per tool call, each with the matching tool_call_id.
        This is required by the OpenAI/LiteLLM tool-calling API format.
        """
        for name, result, tool_call_id in results:
            content = str(result.data) if result.success else f"Error: {result.error}"
            self.messages.append({
                "role": "tool",
                "tool_call_id": tool_call_id,
                "content": content,
            })

    def _extract_findings_from_conversation(self) -> list[Finding]:
        """Extract structured findings from agent's final analysis.

        Strategy:
        1. Always run deterministic analyzers (fast, correct, no LLM needed)
        2. If LLM participated, enhance findings with its reasoning
        3. Return enriched findings
        """
        # Step 1: Run deterministic analyzers (backbone)
        findings = self._run_deterministic_analyzers()

        # Step 2: If LLM was involved, enhance with its insights
        if len(self.messages) > 2:  # More than just system + initial prompt
            findings = self._enhance_findings_with_llm_reasoning(findings)

        return findings

    def _run_deterministic_analyzers(self) -> list[Finding]:
        """Run all deterministic analyzers to get core findings."""
        from host_doctor.analyzers.auth import analyze_authentication
        from host_doctor.analyzers.network import analyze_network
        from host_doctor.analyzers.policy import analyze_policy
        from host_doctor.analyzers.coverage import (
            analyze_plugin_coverage,
            detect_missing_critical_families,
        )
        from host_doctor.analyzers.diagnostics import detect_missing_debug_data

        findings = []
        findings.extend(analyze_authentication(self.host_data, self.scan_config))
        findings.extend(analyze_network(self.host_data, self.scan_config))
        findings.extend(analyze_policy(self.host_data, self.scan_config))
        findings.extend(analyze_plugin_coverage(self.host_data, self.scan_config))
        findings.extend(detect_missing_critical_families(self.host_data))

        from host_doctor.analyzers.tuning import analyze_scan_tuning
        findings.extend(analyze_scan_tuning(self.host_data, self.scan_config))

        from host_doctor.analyzers.validation import analyze_validation
        findings.extend(analyze_validation(self.host_data, self.scan_config))

        from host_doctor.analyzers.discovery import analyze_discovery
        findings.extend(analyze_discovery(self.host_data, self.scan_config))

        from host_doctor.analyzers.scanner_route import analyze_scanner_route
        findings.extend(analyze_scanner_route(self.host_data, self.scan_config))

        # Run debug detection last so it can see what other analyzers found
        findings.extend(detect_missing_debug_data(self.host_data, self.scan_config, findings))

        # Launched-plugins / audit-trail enrichment (sees all prior findings).
        from host_doctor.analyzers.launched_plugins import analyze_launched_plugins
        findings.extend(analyze_launched_plugins(self.host_data, self.scan_config, findings))

        return findings

    def _enhance_findings_with_llm_reasoning(self, findings: list[Finding]) -> list[Finding]:
        """Enhance deterministic findings with LLM's narrative and insights.

        Args:
            findings: Deterministic findings from analyzers

        Returns:
            Enhanced findings with LLM narratives added
        """
        if not findings:
            return findings

        # Ask LLM to provide root cause narrative for the findings
        llm_insights = self._request_llm_narrative(findings)

        if not llm_insights:
            return findings  # Graceful fallback

        # Match LLM insights to findings and enrich them
        for finding in findings:
            # Try to find matching insight by category and plugin IDs
            matching_insight = self._find_matching_insight(finding, llm_insights)
            if matching_insight:
                finding.llm_narrative = matching_insight

        # Optionally add executive summary finding
        executive_summary = llm_insights.get("summary")
        if executive_summary:
            summary_finding = Finding(
                category=FindingCategory.MISSING_DIAGNOSTICS,
                severity=Severity.INFO,
                title="Executive Summary",
                description="Overall analysis of scan issues for this host",
                llm_narrative=executive_summary,
            )
            findings.insert(0, summary_finding)  # Put summary first

        return findings

    def _request_llm_narrative(self, findings: list[Finding]) -> dict[str, str]:
        """Request LLM to provide narrative explanations for findings.

        Args:
            findings: Deterministic findings

        Returns:
            Dict mapping finding identifiers to narrative explanations
        """
        if not findings:
            return {}

        # Build summary of findings for LLM to explain
        findings_summary = []
        for i, f in enumerate(findings):
            findings_summary.append(
                f"Finding {i+1}: [{f.category.value}] {f.title}\n"
                f"  Plugins: {f.plugin_ids}\n"
                f"  Evidence: {f.evidence[:2]}"  # First 2 evidence items
            )

        prompt = f"""Based on your investigation, provide root cause narratives for these findings:

{chr(10).join(findings_summary)}

For each finding, provide:
1. Root cause explanation (why this happened, not just what)
2. Specific details from plugin outputs that reveal the underlying issue
3. Context about how this relates to other findings

Also provide an executive summary (key "summary") that explains the overall situation: what's broken, why, and the recommended fix priority.

Format your response as JSON:
{{
  "summary": "2-3 sentence executive summary explaining the core issue and its impact",
  "0": "narrative for finding 1",
  "1": "narrative for finding 2",
  ...
}}

Be specific and cite plugin outputs where relevant. Focus on WHY, not WHAT."""

        self.messages.append({"role": "user", "content": prompt})

        try:
            import litellm
            import json

            response = litellm.completion(
                model=self.model,
                messages=self.messages,
                response_format={"type": "json_object"},
            )

            content = response["choices"][0]["message"]["content"]
            return json.loads(content)

        except Exception as e:
            if self.verbose:
                print(f"[Agent] Failed to get LLM narrative: {e}")
            return {}

    def _find_matching_insight(self, finding: Finding, insights: dict[str, str]) -> Optional[str]:
        """Find the LLM insight that matches this finding.

        Args:
            finding: Deterministic finding
            insights: Dict of finding index -> narrative

        Returns:
            Matching narrative or None
        """
        # For now, use simple index-based matching
        # In future, could do semantic matching by category/plugins
        for idx_str, narrative in insights.items():
            try:
                # Check if this narrative mentions the finding's plugins
                if any(str(pid) in narrative for pid in finding.plugin_ids):
                    return narrative
            except Exception:
                continue

        return None
