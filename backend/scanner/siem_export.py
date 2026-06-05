"""SIEM/Security Appliance export formats for MCP Security Scanner.

Supported formats:
  - CEF (Common Event Format) — ArcSight, Splunk, Sentinel, QRadar, Elastic
  - LEEF (Log Event Extended Format) — IBM QRadar native
  - Syslog RFC 5424 — Universal SIEM ingestion
  - NDJSON (Newline-Delimited JSON) — Splunk, Elastic bulk ingest
  - CSV — Legacy SIEM, spreadsheet import
  - W3C Extended Log — IIS, web appliances
"""

from __future__ import annotations

import csv
import io
import json
from datetime import datetime, timezone
from scanner.models import Finding, ScanResult, Severity


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _severity_to_syslog(severity: Severity) -> int:
    """Map scanner severity to syslog severity level (0=Emergency, 7=Debug)."""
    mapping = {
        Severity.CRITICAL: 2,   # Critical
        Severity.HIGH: 3,       # Error
        Severity.MEDIUM: 4,     # Warning
        Severity.LOW: 5,        # Notice
        Severity.INFO: 6,       # Informational
    }
    return mapping.get(severity, 6)


def _severity_to_cef(severity: Severity) -> int:
    """Map scanner severity to CEF severity (0-10)."""
    mapping = {
        Severity.CRITICAL: 10,
        Severity.HIGH: 7,
        Severity.MEDIUM: 5,
        Severity.LOW: 3,
        Severity.INFO: 1,
    }
    return mapping.get(severity, 5)


def _escape_cef(value: str) -> str:
    """Escape special characters for CEF extension fields."""
    return str(value).replace("\\", "\\\\").replace("=", "\\=").replace("\n", "\\n").replace("\r", "")


def _escape_leef(value: str) -> str:
    """Escape special characters for LEEF extension fields."""
    return str(value).replace("\\", "\\\\").replace("|", "\\|").replace("\n", "\\n").replace("\r", "")


def _now_rfc5424() -> str:
    """Return current time in RFC 5424 format."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")


# ---------------------------------------------------------------------------
# CEF (Common Event Format)
# Spec: https://www.microfocus.com/documentation/arcsight/arcsight-smartconnectors-8.7/
# ---------------------------------------------------------------------------

def generate_cef(result: ScanResult) -> str:
    """Generate CEF-formatted output for each finding.

    CEF format:
    CEF:Version|Device Vendor|Device Product|Device Version|
    Signature ID|Name|Severity|Extension
    """
    lines = []
    vendor = "OWL"
    product = "MCP Scanner"
    version = "0.1.0"

    for finding in result.findings:
        timestamp = result.scan_time.strftime("%b %d %Y %H:%M:%S UTC")
        severity = _severity_to_cef(finding.severity)
        signature_id = finding.check_id

        # Build extension fields
        ext = {
            "rt": timestamp,
            "msg": _escape_cef(finding.description),
            "cs1": _escape_cef(finding.check_id),
            "cs1Label": "CheckID",
            "cs2": _escape_cef(finding.owasp_code),
            "cs2Label": "OWASPCode",
        }
        if finding.server:
            ext["shost"] = _escape_cef(finding.server)
        if finding.tool:
            ext["suser"] = _escape_cef(finding.tool)
        if finding.evidence:
            ext["reason"] = _escape_cef(finding.evidence)
        if finding.remediation:
            ext["cat"] = _escape_cef(finding.remediation)

        ext_str = " ".join(f"{k}={v}" for k, v in ext.items())

        line = (
            f"CEF:0|{vendor}|{product}|{version}|"
            f"{signature_id}|{_escape_cef(finding.title)}|{severity}|{ext_str}"
        )
        lines.append(line)

    if not lines:
        # Emit a single "clean scan" event
        timestamp = result.scan_time.strftime("%b %d %Y %H:%M:%S UTC")
        ext = {
            "rt": timestamp,
            "msg": _escape_cef(f"Clean scan: {len(result.servers)} servers scanned, 0 findings"),
            "cs1": "CLEAN",
            "cs1Label": "ScanResult",
        }
        ext_str = " ".join(f"{k}={v}" for k, v in ext.items())
        lines.append(
            f"CEF:0|{vendor}|{product}|{version}|CLEAN|Clean Scan|0|{ext_str}"
        )

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# LEEF (Log Event Extended Format)
# Spec: IBM QRadar LEEF 2.0
# ---------------------------------------------------------------------------

def generate_leef(result: ScanResult) -> str:
    """Generate LEEF 2.0-formatted output for each finding.

    LEEF format:
    LEEF:2.0|Vendor|Product|Version|EventID|key=value\\tkey=value...
    """
    lines = []
    vendor = "OWL"
    product = "MCPScanner"
    version = "0.1.0"
    delimiter = "\t"

    for finding in result.findings:
        timestamp = result.scan_time.strftime("%Y-%m-%d %H:%M:%S UTC")
        attrs = {
            "devTime": timestamp,
            "devTimeFormat": "yyyy-MM-dd HH:mm:ss",
            "eventId": finding.check_id,
            "findingTitle": _escape_leef(finding.title),
            "severity": finding.severity.name,
            "msg": _escape_leef(finding.description),
        }
        if finding.server:
            attrs["src"] = _escape_leef(finding.server)
        if finding.tool:
            attrs["usrName"] = _escape_leef(finding.tool)
        if finding.owasp_code:
            attrs["owaspCode"] = _escape_leef(finding.owasp_code)
        if finding.evidence:
            attrs["evidence"] = _escape_leef(finding.evidence)
        if finding.remediation:
            attrs["remediation"] = _escape_leef(finding.remediation)

        attr_str = delimiter.join(f"{k}={v}" for k, v in attrs.items())
        lines.append(f"LEEF:2.0|{vendor}|{product}|{version}|{finding.check_id}|{attr_str}")

    if not lines:
        timestamp = result.scan_time.strftime("%Y-%m-%dT%H:%M:%S.000Z")
        attrs = {
            "devTime": timestamp,
            "eventId": "CLEAN",
            "msg": _escape_leef(f"Clean scan: {len(result.servers)} servers scanned, 0 findings"),
            "severity": "INFO",
        }
        attr_str = delimiter.join(f"{k}={v}" for k, v in attrs.items())
        lines.append(f"LEEF:2.0|{vendor}|{product}|{version}|CLEAN|{attr_str}")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Syslog RFC 5424
# ---------------------------------------------------------------------------

def generate_syslog(result: ScanResult) -> str:
    """Generate RFC 5424 syslog output for each finding.

    Format:
    <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID [SD-ID] MSG
    """
    lines = []
    hostname = "mcp-scanner"
    app_name = "mcp-scanner"
    prival = 3 * 8 + 6  # facility=3 (system daemon), severity varies per message

    for finding in result.findings:
        sev = _severity_to_syslog(finding.severity)
        pri = 3 * 8 + sev  # facility=3, severity=finding severity
        timestamp = _now_rfc5424()
        msgid = finding.check_id

        # Structured data: custom SD-ID with finding details
        sd_data = f"[finding@32473 check_id=\"{finding.check_id}\" severity=\"{finding.severity.name}\""
        if finding.server:
            sd_data += f" server=\"{finding.server}\""
        if finding.tool:
            sd_data += f" tool=\"{finding.tool}\""
        if finding.owasp_code:
            sd_data += f" owasp_code=\"{finding.owasp_code}\""
        sd_data += "]"

        msg = f"{finding.title}: {finding.description}"
        if finding.evidence:
            msg += f" | evidence: {finding.evidence}"

        line = f"<{pri}>1 {timestamp} {hostname} {app_name} - {msgid} {sd_data} {msg}"
        lines.append(line)

    if not lines:
        pri = 3 * 8 + 6  # INFO
        timestamp = _now_rfc5424()
        sd_data = f"[finding@32473 result=\"clean\" servers=\"{len(result.servers)}\"]"
        msg = f"Clean scan: {len(result.servers)} servers scanned, 0 findings"
        line = f"<{pri}>1 {timestamp} {hostname} {app_name} - CLEAN {sd_data} {msg}"
        lines.append(line)

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# NDJSON (Newline-Delimited JSON)
# ---------------------------------------------------------------------------

def generate_ndjson(result: ScanResult) -> str:
    """Generate NDJSON output — one JSON object per line.

    Each finding is a separate JSON document. Compatible with
    Splunk HEC, Elastic bulk API, Datadog, etc.
    """
    lines = []
    for finding in result.findings:
        record = {
            "timestamp": result.scan_time.isoformat(),
            "scan_target": result.target,
            "check_id": finding.check_id,
            "severity": finding.severity.name,
            "title": finding.title,
            "description": finding.description,
            "server": finding.server,
            "tool": finding.tool,
            "owasp_code": finding.owasp_code,
            "evidence": finding.evidence,
            "remediation": finding.remediation,
        }
        lines.append(json.dumps(record, default=str))

    if not lines:
        lines.append(json.dumps({
            "timestamp": result.scan_time.isoformat(),
            "scan_target": result.target,
            "result": "clean",
            "servers_scanned": len(result.servers),
            "findings": 0,
        }))

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# CSV
# ---------------------------------------------------------------------------

def generate_csv(result: ScanResult) -> str:
    """Generate CSV output for spreadsheet/legacy SIEM import."""
    output = io.StringIO()
    writer = csv.writer(output)

    # Header
    writer.writerow([
        "Timestamp", "CheckID", "Severity", "Title", "Description",
        "Server", "Tool", "OWASP", "Evidence", "Remediation",
    ])

    for finding in result.findings:
        writer.writerow([
            result.scan_time.isoformat(),
            finding.check_id,
            finding.severity.name,
            finding.title,
            finding.description,
            finding.server,
            finding.tool,
            finding.owasp_code,
            finding.evidence,
            finding.remediation,
        ])

    if not result.findings:
        writer.writerow([
            result.scan_time.isoformat(),
            "CLEAN", "INFO", "Clean Scan",
            f"{len(result.servers)} servers scanned, 0 findings",
            "", "", "", "", "",
        ])

    return output.getvalue()


# ---------------------------------------------------------------------------
# W3C Extended Log Format
# ---------------------------------------------------------------------------

def generate_w3c(result: ScanResult) -> str:
    """Generate W3C Extended Log Format output.

    Compatible with IIS log parsers, web appliances, and tools that
    accept W3C structured logs.
    """
    lines = []
    lines.append("#Software: MCP Scanner 0.1.0")
    lines.append("#Version: 1.0")
    lines.append(f"#Date: {_now_rfc5424()}")
    lines.append("#Fields: date time c-ip cs-username s-ip s-port cs-method cs-uri-stem sc-status sc-bytes cs-bytes time-taken x-check-id x-severity x-event-id cs-CheckID cs-OWASP x-title x-description x-server x-tool x-evidence x-remediation")
    # Simplified W3C output — map finding fields to W3C columns where practical
    for finding in result.findings:
        timestamp = result.scan_time.strftime("%Y-%m-%d %H:%M:%S")
        # W3C uses spaces to delimit — use available fields
        row = " ".join([
            result.scan_time.strftime("%Y-%m-%d"),
            result.scan_time.strftime("%H:%M:%S"),
            finding.server or "-",
            "-",
            "-",
            "-",
            "SCAN",
            f"/mcp-scan/{finding.check_id}",
            "200",
            "0",
            "0",
            "0",
            finding.check_id,
            finding.severity.name,
            finding.owasp_code or "-",
            finding.check_id,
            finding.owasp_code or "-",
            finding.title.replace(" ", "+"),
            finding.description.replace(" ", "+")[:100],
            finding.server or "-",
            finding.tool or "-",
            finding.evidence.replace(" ", "+")[:100] if finding.evidence else "-",
            finding.remediation.replace(" ", "+")[:100] if finding.remediation else "-",
        ])
        lines.append(row)

    if not result.findings:
        timestamp = result.scan_time.strftime("%Y-%m-%d %H:%M:%S")
        lines.append(f"{result.scan_time.strftime('%Y-%m-%d')} {result.scan_time.strftime('%H:%M:%S')} - - - - - SCAN /mcp-scan/clean 200 0 0 0 CLEAN INFO CLEAN - Clean+Scan - - - - -")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Export dispatcher
# ---------------------------------------------------------------------------

FORMAT_GENERATORS = {
    "cef": generate_cef,
    "leef": generate_leef,
    "syslog": generate_syslog,
    "syslog-rfc5424": generate_syslog,
    "ndjson": generate_ndjson,
    "csv": generate_csv,
    "w3c": generate_w3c,
}


def generate_export(result: ScanResult, fmt: str) -> str:
    """Generate output in the specified SIEM format."""
    generator = FORMAT_GENERATORS.get(fmt)
    if not generator:
        raise ValueError(
            f"Unknown format: {fmt}. "
            f"Supported: {', '.join(sorted(FORMAT_GENERATORS.keys()))}"
        )
    return generator(result)
