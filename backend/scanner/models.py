"""Data models for MCP Security Scanner."""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from datetime import datetime, timezone


class Severity(enum.IntEnum):
    CRITICAL = 0
    HIGH = 1
    MEDIUM = 2
    LOW = 3
    INFO = 4


@dataclass
class Finding:
    check_id: str
    severity: Severity
    title: str
    description: str
    server: str = ""
    tool: str = ""
    evidence: str = ""
    remediation: str = ""
    owasp_code: str = ""
    location: str = ""
    owasp_mapping: str = ""
    cve_reference: str = ""

    def to_dict(self) -> dict:
        return {
            "check_id": self.check_id,
            "severity": self.severity.name,
            "title": self.title,
            "description": self.description,
            "server": self.server,
            "tool": self.tool,
            "evidence": self.evidence,
            "remediation": self.remediation,
            "owasp_code": self.owasp_code,
            "location": self.location or self.server or self.tool or "",
            "owasp_mapping": self.owasp_mapping or self.owasp_code or "",
            "cve_reference": self.cve_reference,
        }


@dataclass
class MCPServer:
    name: str
    command: str = ""
    args: list = field(default_factory=list)
    env: dict = field(default_factory=dict)
    url: str = ""
    transport: str = ""
    headers: dict = field(default_factory=dict)
    tools: list = field(default_factory=list)
    auth: dict = field(default_factory=dict)

    @classmethod
    def from_dict(cls, name: str, data: dict) -> "MCPServer":
        return cls(
            name=name,
            command=data.get("command", ""),
            args=data.get("args", []),
            env=data.get("env", {}),
            url=data.get("url", ""),
            transport=data.get("transport", ""),
            headers=data.get("headers", {}),
            tools=data.get("tools", []),
            auth=data.get("auth", {}),
        )


ScanResult = None  # forward-declared; defined below


@dataclass
class ScanResult:
    target: str = ""
    servers: list = field(default_factory=list)
    findings: list = field(default_factory=list)
    scan_time: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    @property
    def summary(self) -> dict:
        return {
            "target": self.target,
            "servers_scanned": len(self.servers),
            "total_findings": self.total_count,
            "severity_counts": {
                "CRITICAL": self.critical_count,
                "HIGH": self.high_count,
                "MEDIUM": self.medium_count,
                "LOW": self.low_count,
                "INFO": self.info_count,
            },
        }

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.CRITICAL)

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.HIGH)

    @property
    def medium_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.MEDIUM)

    @property
    def low_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.LOW)

    @property
    def info_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.INFO)

    @property
    def total_count(self) -> int:
        return len(self.findings)

    @property
    def exit_code(self) -> int:
        if self.critical_count > 0:
            return 2
        if self.high_count > 0:
            return 1
        if self.medium_count > 0:
            return 1
        if self.low_count > 0:
            return 1
        return 0

    def to_dict(self) -> dict:
        return {
            "summary": self.summary,
            "target": self.target,
            "scan_time": self.scan_time.isoformat(),
            "servers_scanned": len(self.servers),
            "findings_total": self.total_count,
            "severity_counts": {
                "CRITICAL": self.critical_count,
                "HIGH": self.high_count,
                "MEDIUM": self.medium_count,
                "LOW": self.low_count,
                "INFO": self.info_count,
            },
            "exit_code": self.exit_code,
            "findings": [f.to_dict() for f in self.findings],
        }
