"""Report generation for MCP Security Scanner."""

from __future__ import annotations

import json
from pathlib import Path

from rich.console import Console
from rich.table import Table
from rich.panel import Panel

from scanner.models import Finding, ScanResult, Severity


SEVERITY_COLORS = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "blue",
    Severity.INFO: "dim",
}

SEVERITY_ICONS = {
    Severity.CRITICAL: "[CRIT]",
    Severity.HIGH: "[HIGH]",
    Severity.MEDIUM: "[MED] ",
    Severity.LOW: "[LOW] ",
    Severity.INFO: "[INFO]",
}


def generate_markdown(result: ScanResult) -> str:
    lines = []
    lines.append("# MCP Security Scan Report")
    lines.append("")
    lines.append(f"**Target:** `{result.target}`")
    lines.append(f"**Scan Time:** {result.scan_time.isoformat()}")
    lines.append(f"**Servers Scanned:** {len(result.servers)}")
    lines.append(f"**Total Findings:** {result.total_count}")
    lines.append("")
    lines.append("## Severity Summary")
    lines.append("")
    lines.append("| Severity | Count |")
    lines.append("|----------|-------|")
    for sev in Severity:
        count = sum(1 for f in result.findings if f.severity == sev)
        if count > 0 or sev != Severity.INFO:
            lines.append(f"| {sev.name} | {count} |")
    lines.append("")

    if result.findings:
        lines.append("## Findings")
        lines.append("")
        for i, finding in enumerate(result.findings, 1):
            lines.append(f"### {i}. [{finding.check_id}] {finding.title}")
            lines.append("")
            lines.append(f"- **Severity:** {finding.severity.name}")
            if finding.server:
                lines.append(f"- **Server:** `{finding.server}`")
            if finding.tool:
                lines.append(f"- **Tool:** `{finding.tool}`")
            if finding.owasp_code:
                lines.append(f"- **OWASP:** {finding.owasp_code}")
            lines.append("")
            lines.append(f"**Description:**")
            lines.append(f"{finding.description}")
            lines.append("")
            if finding.evidence:
                lines.append(f"**Evidence:**")
                lines.append("```")
                lines.append(finding.evidence)
                lines.append("```")
                lines.append("")
            if finding.remediation:
                lines.append(f"**Remediation:**")
                lines.append(f"{finding.remediation}")
                lines.append("")
            lines.append("---")
            lines.append("")
    else:
        lines.append("## No Findings")
        lines.append("")
        lines.append("No security issues detected. Configuration appears clean.")
        lines.append("")

    return "\n".join(lines)


def generate_json(result: ScanResult) -> str:
    return json.dumps(result.to_dict(), indent=2)


def print_console_report(result: ScanResult) -> None:
    console = Console()
    console.print()
    console.print(Panel(
        f"[bold]MCP Security Scan Report[/bold]\n"
        f"Target: [cyan]{result.target}[/cyan]\n"
        f"Servers: {len(result.servers)} | "
        f"Findings: [bold]{result.total_count}[/bold] | "
        f"Exit Code: {result.exit_code}",
        title="mcp-scanner",
        border_style="blue",
    ))

    summary_table = Table(title="Severity Summary", show_header=True)
    summary_table.add_column("Severity", style="bold")
    summary_table.add_column("Count", justify="right")
    for sev in Severity:
        count = sum(1 for f in result.findings if f.severity == sev)
        color = SEVERITY_COLORS[sev]
        summary_table.add_row(f"[{color}]{sev.name}[/{color}]", str(count))
    console.print(summary_table)

    if result.findings:
        findings_table = Table(title="Findings", show_header=True, expand=True)
        findings_table.add_column("ID", style="dim", width=10)
        findings_table.add_column("Sev", width=6)
        findings_table.add_column("Title", min_width=30)
        findings_table.add_column("Server", min_width=15)
        findings_table.add_column("Tool", min_width=12)

        for finding in result.findings:
            color = SEVERITY_COLORS[finding.severity]
            icon = SEVERITY_ICONS[finding.severity]
            findings_table.add_row(
                finding.check_id,
                f"[{color}]{icon}[/{color}]",
                finding.title,
                finding.server or "-",
                finding.tool or "-",
            )
        console.print(findings_table)

        critical_high = [f for f in result.findings
                         if f.severity in (Severity.CRITICAL, Severity.HIGH)]
        if critical_high:
            console.print()
            console.print("[bold red]Critical / High Details:[/bold red]")
            for finding in critical_high:
                detail = f"[dim]{finding.description}[/dim]"
                if finding.evidence:
                    detail += f"\n\n[yellow]Evidence:[/yellow] {finding.evidence}"
                if finding.remediation:
                    detail += f"\n\n[green]Fix:[/green] {finding.remediation}"
                console.print(Panel(
                    detail,
                    title=f"[{SEVERITY_COLORS[finding.severity]}]{finding.check_id} - {finding.title}[/{SEVERITY_COLORS[finding.severity]}]",
                    border_style=SEVERITY_COLORS[finding.severity].split()[-1],
                ))
    else:
        console.print()
        console.print("[green]No findings - configuration is clean.[/green]")

    console.print()
