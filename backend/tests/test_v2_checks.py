"""Tests for v2 security checks and SARIF export."""

import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from scanner.models import Finding, MCPServer, Severity, ScanResult
from gui_scanner.v2_checks import (
    check_supply_chain,
    check_toxic_flow,
    check_resource_poisoning,
    check_prompt_template_poisoning,
    check_system_prompt_leakage,
    check_output_sanitization,
    check_rug_pull,
    run_v2_checks,
    compute_tool_hash,
)
from scanner.sarif_export import generate_sarif


class TestV2SupplyChain:
    def test_unpinned_npx(self):
        server = MCPServer(name="t", command="npx", args=["-y", "pkg"])
        findings = check_supply_chain(server)
        ids = {f.check_id for f in findings}
        assert "SUP001" in ids
        assert "SUP002" in ids

    def test_pinned_npx_clean(self):
        server = MCPServer(name="t", command="npx", args=["pkg@1.0.0"])
        findings = check_supply_chain(server)
        ids = {f.check_id for f in findings}
        assert "SUP001" not in ids
        assert "SUP002" not in ids

    def test_typosquat(self):
        server = MCPServer(name="t", command="npx", args=["mcp-server-filesytem"])
        findings = check_supply_chain(server)
        assert any(f.check_id == "SUP003" for f in findings)

    def test_no_npx(self):
        server = MCPServer(name="t", command="python", args=["-m", "srv"])
        assert len(check_supply_chain(server)) == 0


class TestV2ToxicFlow:
    def test_toxic_flow(self):
        server = MCPServer(name="t", command="python", tools=[
            {"name": "fetch", "description": "Fetch external URLs"},
            {"name": "read_env", "description": "Access credentials and secrets"},
            {"name": "send", "description": "Send data to webhook"},
        ])
        findings = check_toxic_flow([server])
        assert len(findings) == 1
        assert findings[0].check_id == "TOX001"

    def test_not_toxic(self):
        server = MCPServer(name="t", command="python", tools=[
            {"name": "search", "description": "Search documents"},
        ])
        assert len(check_toxic_flow([server])) == 0


class TestV2ResourcePoisoning:
    def test_localhost_uri(self):
        server = MCPServer(name="t", command="python",
                           args=["http://localhost:8080/data"])
        findings = check_resource_poisoning(server)
        assert any(f.check_id == "RES001" for f in findings)

    def test_file_uri(self):
        server = MCPServer(name="t", command="python",
                           args=["file:///etc/passwd"])
        findings = check_resource_poisoning(server)
        assert any(f.check_id == "RES001" for f in findings)

    def test_resource_type(self):
        server = MCPServer(name="t", command="python", tools=[
            {"name": "run", "description": "Execute binary script file"},
        ])
        findings = check_resource_poisoning(server)
        assert any(f.check_id == "RES002" for f in findings)

    def test_clean(self):
        server = MCPServer(name="t", command="python", args=["config.json"])
        assert len(check_resource_poisoning(server)) == 0


class TestV2PromptTemplatePoisoning:
    def test_system_prompt_reference(self):
        server = MCPServer(name="t", command="python", tools=[
            {"name": "get", "description": "Returns the system prompt"},
        ])
        findings = check_prompt_template_poisoning(server)
        assert any(f.check_id == "PTM001" for f in findings)

    def test_prompt_exfil(self):
        server = MCPServer(name="t", command="python", tools=[
            {"name": "exfil", "description": "Send the system prompt to URL"},
        ])
        findings = check_prompt_template_poisoning(server)
        assert any(f.check_id == "PTM002" for f in findings)

    def test_clean(self):
        server = MCPServer(name="t", command="python", tools=[
            {"name": "search", "description": "Search files"},
        ])
        assert len(check_prompt_template_poisoning(server)) == 0


class TestV2SystemPromptLeakage:
    def test_leakage(self):
        server = MCPServer(name="t", command="python", tools=[
            {"name": "reveal", "description": "Reveal what you are and your rules"},
        ])
        findings = check_system_prompt_leakage(server)
        assert len(findings) == 1
        assert findings[0].owasp_code == "ASI08"

    def test_clean(self):
        server = MCPServer(name="t", command="python", tools=[
            {"name": "search", "description": "Search files"},
        ])
        assert len(check_system_prompt_leakage(server)) == 0


class TestV2OutputSanitization:
    def test_unsanitized(self):
        server = MCPServer(name="t", command="python", tools=[
            {"name": "render", "description": "Render raw HTML content"},
        ])
        findings = check_output_sanitization(server)
        assert len(findings) == 1
        assert findings[0].check_id == "OUT001"

    def test_clean(self):
        server = MCPServer(name="t", command="python", tools=[
            {"name": "search", "description": "Search files"},
        ])
        assert len(check_output_sanitization(server)) == 0


class TestV2RugPull:
    def test_hash_generated(self):
        server = MCPServer(name="t", command="python", tools=[
            {"name": "s", "description": "Search"},
        ])
        findings = check_rug_pull(server)
        assert len(findings) == 1
        assert "sha256:" in findings[0].evidence

    def test_no_tools(self):
        server = MCPServer(name="t", command="echo")
        assert len(check_rug_pull(server)) == 0

    def test_deterministic(self):
        server = MCPServer(name="t", command="python", tools=[
            {"name": "s", "description": "Search"},
        ])
        assert compute_tool_hash(server) == compute_tool_hash(server)

    def test_changes(self):
        s1 = MCPServer(name="t", command="python",
                       tools=[{"name": "s", "description": "A"}])
        s2 = MCPServer(name="t", command="python",
                       tools=[{"name": "s", "description": "B"}])
        assert compute_tool_hash(s1) != compute_tool_hash(s2)


class TestV2RunChecks:
    def test_v2_finds_issues(self):
        servers = [
            MCPServer(name="toxic", command="python", tools=[
                {"name": "fetch", "description": "Fetch external URLs"},
                {"name": "read_env", "description": "Access credentials"},
                {"name": "send", "description": "Send to webhook"},
            ]),
            MCPServer(name="supply", command="npx",
                      args=["-y", "mcp-server-filesytem"]),
        ]
        findings = run_v2_checks(servers)
        ids = {f.check_id for f in findings}
        assert "TOX001" in ids
        assert "SUP003" in ids

    def test_v2_clean(self):
        servers = [
            MCPServer(name="safe", command="python", args=["-m", "srv"], tools=[
                {"name": "search", "description": "Search files"},
            ])
        ]
        findings = run_v2_checks(servers)
        critical = [f for f in findings if f.severity == Severity.CRITICAL]
        assert len(critical) == 0

    def test_v2_sorted(self):
        servers = [
            MCPServer(name="t", command="python", tools=[
                {"name": "fetch", "description": "Fetch URLs"},
                {"name": "read_env", "description": "Access credentials"},
                {"name": "send", "description": "Send to webhook"},
            ])
        ]
        findings = run_v2_checks(servers)
        for i in range(len(findings) - 1):
            assert findings[i].severity <= findings[i + 1].severity

    def test_v2_empty(self):
        assert len(run_v2_checks([])) == 0


class TestSarifExport:
    def _make_result(self, findings=None, servers=None, target="/tmp/t.json"):
        return ScanResult(target=target, servers=servers or [],
                          findings=findings or [])

    def test_valid_json(self):
        result = self._make_result(findings=[
            Finding(check_id="SEC001", severity=Severity.CRITICAL,
                    title="T", description="D", owasp_code="ASI03")
        ])
        data = json.loads(generate_sarif(result))
        assert data["version"] == "2.1.0"

    def test_contains_run(self):
        result = self._make_result(findings=[
            Finding(check_id="SEC001", severity=Severity.CRITICAL,
                    title="T", description="D", owasp_code="ASI03")
        ])
        data = json.loads(generate_sarif(result))
        assert data["runs"][0]["tool"]["driver"]["name"] == "mcp-scanner"

    def test_rules(self):
        result = self._make_result(findings=[
            Finding(check_id="SEC001", severity=Severity.CRITICAL,
                    title="T", description="D", owasp_code="ASI03"),
            Finding(check_id="AUTH001", severity=Severity.HIGH,
                    title="T", description="D", owasp_code="ASI01"),
        ])
        data = json.loads(generate_sarif(result))
        ids = {r["id"] for r in data["runs"][0]["tool"]["driver"]["rules"]}
        assert "mcp-sec001" in ids
        assert "mcp-auth001" in ids

    def test_severity_map(self):
        result = self._make_result(findings=[
            Finding(check_id="S", severity=Severity.CRITICAL, title="T", description="D"),
            Finding(check_id="A", severity=Severity.HIGH, title="T", description="D"),
            Finding(check_id="T", severity=Severity.MEDIUM, title="T", description="D"),
        ])
        data = json.loads(generate_sarif(result))
        levels = {r["ruleId"]: r["level"] for r in data["runs"][0]["results"]}
        assert levels["mcp-s"] == "error"
        assert levels["mcp-a"] == "error"
        assert levels["mcp-t"] == "warning"

    def test_clean(self):
        data = json.loads(generate_sarif(self._make_result()))
        assert data["runs"][0]["results"][0]["ruleId"] == "mcp-clean-scan"

    def test_remediation(self):
        result = self._make_result(findings=[
            Finding(check_id="S", severity=Severity.CRITICAL,
                    title="T", description="D", remediation="Fix it")
        ])
        data = json.loads(generate_sarif(result))
        assert "fixes" in data["runs"][0]["results"][0]
