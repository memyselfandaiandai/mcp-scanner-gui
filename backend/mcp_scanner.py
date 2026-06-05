"""CLI entry point for MCP Security Scanner."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import click
import yaml

from scanner.checks import run_checks
from scanner.models import MCPServer, ScanResult
from scanner.reporter import generate_json, generate_markdown, print_console_report
from scanner.siem_export import generate_export


def parse_config(path: str) -> list:
    p = Path(path)
    if not p.exists():
        raise click.ClickException(f"Config file not found: {path}")
    text = p.read_text()
    if p.suffix in (".yaml", ".yml"):
        data = yaml.safe_load(text)
    else:
        data = json.loads(text)
    servers = []
    servers_block = data.get("mcpServers", data)
    for name, config in servers_block.items():
        if isinstance(config, dict):
            servers.append(MCPServer.from_dict(name, config))
    return servers


SUPPORTED_FORMATS = [
    "console", "markdown", "json",
    "cef", "leef", "syslog", "syslog-rfc5424",
    "ndjson", "csv", "w3c",
]


@click.group()
@click.version_option(version="0.1.0", prog_name="mcp-scanner")
def main():
    """MCP Security Scanner - audit MCP server configurations for security issues."""
    pass


@main.command("scan")
@click.argument("config_path", type=click.Path(exists=True))
@click.option("--output", "-o", "output_path", type=click.Path(), default=None)
@click.option("--format", "-f", "fmt",
              type=click.Choice(SUPPORTED_FORMATS, case_sensitive=False),
              default="console")
@click.option("--min-severity", default="INFO")
def scan(config_path, output_path, fmt, min_severity):
    from scanner.models import Severity
    servers = parse_config(config_path)
    findings = run_checks(servers)
    min_sev = Severity[min_severity]
    findings = [f for f in findings if f.severity <= min_sev]
    result = ScanResult(
        target=str(Path(config_path).resolve()),
        servers=servers,
        findings=findings,
    )

    if fmt == "console":
        print_console_report(result)
    elif fmt == "markdown":
        report = generate_markdown(result)
        if output_path:
            Path(output_path).write_text(report)
            click.echo(f"Markdown report written to {output_path}")
        else:
            click.echo(report)
    elif fmt == "json":
        report = generate_json(result)
        if output_path:
            Path(output_path).write_text(report)
            click.echo(f"JSON report written to {output_path}")
        else:
            click.echo(report)
    else:
        # SIEM export formats
        report = generate_export(result, fmt)
        if output_path:
            Path(output_path).write_text(report)
            click.echo(f"{fmt.upper()} report written to {output_path}")
        else:
            click.echo(report)

    sys.exit(result.exit_code)


@main.command("audit")
@click.argument("config_path", type=click.Path(exists=True))
@click.option("--output", "-o", "output_path", type=click.Path(), default=None)
@click.option("--verbose", "-v", is_flag=True)
def audit(config_path, output_path, verbose):
    servers = parse_config(config_path)
    findings = run_checks(servers)
    result = ScanResult(
        target=str(Path(config_path).resolve()),
        servers=servers,
        findings=findings,
    )
    print_console_report(result)
    json_report = generate_json(result)
    if output_path:
        Path(output_path).write_text(json_report)
        click.echo(f"JSON report written to {output_path}")
    elif verbose:
        click.echo("\n--- JSON Report ---")
        click.echo(json_report)
    sys.exit(result.exit_code)


if __name__ == "__main__":
    main()
