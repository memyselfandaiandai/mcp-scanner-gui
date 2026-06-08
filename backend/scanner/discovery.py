"""Discovery mode for MCP Security Scanner.

Auto-detects MCP server configurations from known AI client applications:
- Claude Desktop
- Cursor
- Windsurf
- VS Code
- Cline
- Continue
- Gemini CLI
- Custom paths
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class DiscoveredConfig:
    client: str
    path: str
    server_count: int = 0
    error: str = ""


# Known config file locations per client
_KNOWN_PATHS = {
    "claude_desktop": [
        "~/.claude/claude_desktop_config.json",
        "~/Library/Application Support/Claude/claude_desktop_config.json",
        "%APPDATA%/Claude/claude_desktop_config.json",
    ],
    "cursor": [
        "~/.cursor/mcp_config.json",
        "~/.cursor/settings.json",
        "~/.config/cursor/mcp_config.json",
    ],
    "windsurf": [
        "~/.windsurf/mcp_config.json",
        "~/.config/windsurf/mcp_config.json",
    ],
    "vscode": [
        "~/.vscode/settings.json",
        "~/.vscode/mcp.json",
        ".vscode/mcp.json",
        ".vscode/settings.json",
    ],
    "cline": [
        "~/.cline/config.json",
    ],
    "continue": [
        "~/.continue/config.json",
    ],
    "gemini_cli": [
        "~/.gemini/settings.json",
    ],
}


def _expand_path(path: str, home: Path) -> Path:
    """Expand environment variables and ~ in path."""
    expanded = path.replace("~", str(home))
    # Handle Windows %APPDATA% style
    for env_var in ("APPDATA", "HOME", "USERPROFILE"):
        env_val = os.environ.get(env_var, "")
        if env_val:
            expanded = expanded.replace(f"%{env_var}%", env_val)
    return Path(expanded)


def _count_servers(config_path: Path) -> int:
    """Count MCP servers in a config file."""
    try:
        text = config_path.read_text(encoding="utf-8", errors="ignore")
        # Skip workspace files that reference MCP but don't define servers
        data = json.loads(text)
        if isinstance(data, dict):
            servers = data.get("mcpServers", {})
            if isinstance(servers, dict):
                return len(servers)
            # Some configs nest differently
            for key in ("servers", "mcp_servers", "mcp"):
                if key in data and isinstance(data[key], dict):
                    return len(data[key])
        return 0
    except Exception:
        return 0


def discover(home: Path | None = None) -> list:
    """Discover MCP configurations on the system.

    Args:
        home: Home directory to search. Defaults to current user's home.

    Returns:
        List of DiscoveredConfig objects for each found configuration file.
    """
    if home is None:
        home = Path.home()

    results: list[DiscoveredConfig] = []
    seen_paths: set[str] = set()

    for client, paths in _KNOWN_PATHS.items():
        for path_template in paths:
            config_path = _expand_path(path_template, home)
            resolved = str(config_path.resolve())

            if resolved in seen_paths:
                continue
            seen_paths.add(resolved)

            if config_path.exists():
                try:
                    count = _count_servers(config_path)
                    results.append(DiscoveredConfig(
                        client=client,
                        path=str(config_path),
                        server_count=count,
                    ))
                except Exception as e:
                    results.append(DiscoveredConfig(
                        client=client,
                        path=str(config_path),
                        error=str(e),
                    ))

    return results


if __name__ == "__main__":
    import sys
    home = Path(sys.argv[1]) if len(sys.argv) > 1 else Path.home()
    found = discover(home)

    if not found:
        print("No MCP configurations found.")
    else:
        print(f"Found {len(found)} configuration(s):\n")
        for cfg in found:
            status = f"{cfg.server_count} servers" if not cfg.error else f"error: {cfg.error}"
            print(f"  [{cfg.client}] {cfg.path} ({status})")
