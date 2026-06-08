"""SARIF (Static Analysis Results Interchange Format) output for MCP Security Scanner.

SARIF is the OASIS standard for static analysis tool output.
Supported by: GitHub Advanced Security, Azure DevOps, Visual Studio,
and any SARIF-compatible security dashboard.

Spec: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
"""

from __future__ import annotations

import json
from datetime import datetime, timezone

from scanner.models import Finding, ScanResult, Severity

# Mapping scanner severity to SARIF level
_SEVERITY_TO_SARIF = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "none",
}

# OWASP Agentic code to CWE-like rule ID mapping
_OWASP_TO_RULE = {
    "ASI01": "agent-goal-hijack",
    "ASI02": "tool-misuse-abuse",
    "ASI03": "identity-privilege-abuse",
    "ASI04": "supply-chain-vulnerability",
    "ASI05": "remote-code-execution",
    "ASI06": "memory-context-poisoning",
    "ASI07": "cascading-failures",
    "ASI08": "system-prompt-leakage",
    "ASI09": "human-agent-trust-exploitation",
    "ASI10": "insecure-multi-agent-communication",
}


def generate_sarif(result: ScanResult) -> str:
    """Generate SARIF 2.1.0 JSON output."""
    runs = []

    # Build rules from findings
    rules = {}
    results = []

    for finding in result.findings:
        rule_id = f"mcp-{finding.check_id.lower()}"

        if rule_id not in rules:
            owasp_code = finding.owasp_code or "ASI00"
            cwe_id = _OWASP_TO_RULE.get(owasp_code, "unknown")

            rules[rule_id] = {
                "id": rule_id,
                "name": finding.title.split(":")[0] if ":" in finding.title else finding.title,
                "shortDescription": {
                    "text": finding.title,
                },
                "fullDescription": {
                    "text": finding.description,
                },
                "defaultConfiguration": {
                    "level": _SEVERITY_TO_SARIF.get(finding.severity, "warning"),
                },
                "help": {
                    "text": finding.remediation or "No remediation guidance available.",
                    "markdown": f"**Remediation:** {finding.remediation}" if finding.remediation else "",
                },
                "properties": {
                    "tags": [
                        "security",
                        "mcp",
                        f"owasp-{owasp_code.lower()}",
                        f"severity-{finding.severity.name.lower()}",
                    ],
                    "owaspCode": owasp_code,
                },
                "relationships": [
                    {
                        "target": {
                            "id": cwe_id,
                            "toolComponent": {
                                "name": "OWASP-Agentic-2026",
                                "index": 0,
                            },
                        },
                        "kinds": ["relevant"],
                    }
                ],
            }

        # Build result
        sarif_result = {
            "ruleId": rule_id,
            "level": _SEVERITY_TO_SARIF.get(finding.severity, "warning"),
            "message": {
                "text": finding.title,
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": result.target,
                        },
                        "region": {
                            "startLine": 1,
                            "message": {
                                "text": finding.evidence or finding.description,
                            },
                        },
                    },
                }
            ],
            "properties": {
                "server": finding.server,
                "tool": finding.tool,
                "evidence": finding.evidence,
                "owaspCode": finding.owasp_code,
            },
        }

        # Add fixes if remediation is available
        if finding.remediation:
            sarif_result["fixes"] = [
                {
                    "description": {
                        "text": finding.remediation,
                    },
                }
            ]

        results.append(sarif_result)

    # If no findings, add a clean result
    if not results:
        results.append({
            "ruleId": "mcp-clean-scan",
            "level": "none",
            "message": {
                "text": f"Clean scan: {len(result.servers)} servers scanned, 0 findings",
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": result.target,
                        },
                    },
                }
            ],
        })

    runs.append(
        {
            "tool": {
                "driver": {
                    "name": "mcp-scanner",
                    "version": "0.2.0",
                    "informationUri": "https://github.com/memyselfandaiandai/mcp-scanner",
                    "rules": list(rules.values()),
                },
            },
            "results": results,
            "invocations": [
                {
                    "executionSuccessful": True,
                    "startTimeUtc": result.scan_time.isoformat(),
                    "endTimeUtc": datetime.now(timezone.utc).isoformat(),
                }
            ],
            "artifacts": [
                {
                    "location": {
                        "uri": result.target,
                    },
                    "description": {
                        "text": f"MCP server configuration file ({len(result.servers)} servers)",
                    },
                }
            ],
        }
    )

    sarif_doc = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": runs,
    }

    return json.dumps(sarif_doc, indent=2)
