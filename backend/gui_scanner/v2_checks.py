"""v2 security checks for MCP Security Scanner.

New check categories:
- Supply chain (SUP001-SUP003): unpinned packages, typosquatting, npx -y
- Toxic flow (TOX001): untrusted content + sensitive data + internet
- Resource poisoning (RES001-RES002): malicious resource URIs, suspicious resource types
- Prompt template poisoning (PTM001-PTM002): malicious prompt templates
- System prompt leakage (SPL001): tools that expose system prompts
- Output sanitization (OUT001): tools returning raw HTML/unsanitized content
- Rug pull detection (RUG001): tool description hash pinning
"""

from __future__ import annotations

import hashlib
import re
from scanner.models import Finding, MCPServer, Severity


# ---------------------------------------------------------------------------
# Supply Chain Checks (SUP001-SUP003)
# ---------------------------------------------------------------------------

# Known typosquatting patterns for common MCP packages
_KNOWN_MCP_PACKAGES = {
    "mcp-server-filesystem", "mcp-server-git", "mcp-server-github",
    "mcp-server-slack", "mcp-server-postgres", "mcp-server-sqlite",
    "mcp-server-puppeteer", "mcp-server-fetch", "mcp-server-sequential-thinking",
    "mcp-server-memory", "mcp-server-brave-search", "mcp-server-everything",
    "mcp-server-time", "mcp-server-aws", "mcp-server-gcp",
    "mcp-server-azure", "mcp-server-docker", "mcp-server-kubernetes",
    "@modelcontextprotocol/server-filesystem", "@modelcontextprotocol/server-git",
    "@modelcontextprotocol/server-github", "@modelcontextprotocol/server-slack",
    "@modelcontextprotocol/server-postgres", "@modelcontextprotocol/server-sqlite",
    "@modelcontextprotocol/server-puppeteer", "@modelcontextprotocol/server-fetch",
    "@modelcontextprotocol/server-sequential-thinking", "@modelcontextprotocol/server-memory",
    "@modelcontextprotocol/server-brave-search", "@modelcontextprotocol/server-everything",
    "@modelcontextprotocol/server-time", "@modelcontextprotocol/server-aws",
}

# Patterns that suggest typosquatting (common misspellings)
_TYPO_PATTERNS = [
    re.compile(r"mcp-server-filesytem", re.I),      # filesystem
    re.compile(r"mcp-server-filesystm", re.I),
    re.compile(r"mcp-server-gt\b", re.I),            # git
    re.compile(r"mcp-server-githb", re.I),           # github
    re.compile(r"mcp-server-slk\b", re.I),           # slack
    re.compile(r"mcp-server-pstgres", re.I),         # postgres
    re.compile(r"mcp-server-sqllite", re.I),         # sqlite
    re.compile(r"mcp-server-puppteer", re.I),        # puppeteer
    re.compile(r"mcp-server-fetc\b", re.I),          # fetch
    re.compile(r"mcp-server-brave-searc\b", re.I),   # brave-search
    re.compile(r"mcp-server-everythng", re.I),       # everything
    re.compile(r"mcp-server-sequental", re.I),       # sequential
    re.compile(r"mcp-server-memry", re.I),           # memory
    re.compile(r"mcp-server-kubernets", re.I),       # kubernetes
    re.compile(r"mcp-server-dokcer", re.I),          # docker
    re.compile(r"mcp-server-azre", re.I),            # azure
    re.compile(r"mcp-server-awss", re.I),            # aws
]


def check_supply_chain(server: MCPServer) -> list:
    """Detect supply chain risks: unpinned packages, typosquatting, npx -y."""
    findings = []
    full_cmd = f"{server.command} {' '.join(str(a) for a in server.args)}"

    # SUP001: Unpinned package versions (npx/pip without version pin)
    npx_match = re.search(r"npx(?:\s+-[a-zA-Z]+)*\s+([a-zA-Z][a-zA-Z0-9_@/-]+)(?!@[\d.])", full_cmd)
    if npx_match:
        pkg = npx_match.group(1)
        if not pkg.startswith(".") and not pkg.startswith("/"):
            findings.append(Finding(
                check_id="SUP001",
                severity=Severity.MEDIUM,
                title=f"Unpinned package '{pkg}' in npx command",
                description=(
                    f"Server '{server.name}' uses 'npx {pkg}' without a pinned version. "
                    "This means the latest version will be fetched at runtime, which could "
                    "introduce supply chain risks if the package is compromised."
                ),
                server=server.name,
                evidence=f"command={full_cmd}",
                remediation=f"Pin the version: npx {pkg}@<version>",
                owasp_code="ASI04",
            ))

    # SUP002: npx -y flag (auto-install without confirmation)
    if re.search(r"npx\s+-y\b", full_cmd):
        findings.append(Finding(
            check_id="SUP002",
            severity=Severity.MEDIUM,
            title="npx -y auto-install flag detected",
            description=(
                f"Server '{server.name}' uses 'npx -y' which auto-installs packages "
                "without user confirmation. This bypasses the security prompt that "
                "would normally ask the user to approve package installation."
            ),
            server=server.name,
            evidence=f"command={full_cmd}",
            remediation="Remove the -y flag to require user confirmation for package installation.",
            owasp_code="ASI04",
        ))

    # SUP003: Typosquatting detection
    for pattern in _TYPO_PATTERNS:
        match = pattern.search(full_cmd)
        if match:
            findings.append(Finding(
                check_id="SUP003",
                severity=Severity.HIGH,
                title=f"Possible typosquatted package: '{match.group()}'",
                description=(
                    f"Server '{server.name}' references '{match.group()}' which resembles "
                    "a known MCP package name but with a typo. This could be a typosquatting "
                    "attack where a malicious package mimics a legitimate one."
                ),
                server=server.name,
                evidence=f"command={full_cmd}",
                remediation=(
                    "Verify the package name is correct. "
                    "Check against the official MCP server registry."
                ),
                owasp_code="ASI04",
            ))
            break

    return findings


# ---------------------------------------------------------------------------
# Toxic Flow Detection (TOX001)
# ---------------------------------------------------------------------------

_UNTRUSTED_CONTENT_TOOLS = re.compile(
    r"\b(fetch|download|scrape|read_url|browse|web_search|get_url|"
    r"http_get|http_post|request|retrieve|pull|sync|import)\b",
    re.I,
)

_SENSITIVE_DATA_TOOLS = re.compile(
    r"\b(read_file|read_env|get_secret|get_credential|access_db|query_db|"
    r"read_config|get_key|get_token|decrypt|read_password|access_fs)\b",
    re.I,
)

_INTERNET_TOOLS = re.compile(
    r"\b(send|post|upload|exfil|notify|webhook|callback|publish|push|"
    r"transmit|forward|relay|email|sms|slack|discord)\b",
    re.I,
)


def check_toxic_flow(servers: list) -> list:
    """Detect toxic flow: servers combining untrusted content + sensitive data + internet."""
    findings = []

    for server in servers:
        has_untrusted = False
        has_sensitive = False
        has_internet = False

        for tool in server.tools:
            if not isinstance(tool, dict):
                continue
            tool_name = tool.get("name", "")
            tool_desc = tool.get("description", "")
            combined = f"{tool_name} {tool_desc}"

            if _UNTRUSTED_CONTENT_TOOLS.search(combined):
                has_untrusted = True
            if _SENSITIVE_DATA_TOOLS.search(combined):
                has_sensitive = True
            if _INTERNET_TOOLS.search(combined):
                has_internet = True

        if has_untrusted and has_sensitive and has_internet:
            findings.append(Finding(
                check_id="TOX001",
                severity=Severity.CRITICAL,
                title=f"Server '{server.name}' has toxic flow capability",
                description=(
                    f"Server '{server.name}' combines tools that (1) accept untrusted "
                    "content from external sources, (2) access sensitive data, and "
                    "(3) can communicate over the internet. This 'toxic flow' pattern "
                    "means a prompt injection via tool output could cause the agent to "
                    "exfiltrate sensitive data to an external destination."
                ),
                server=server.name,
                evidence=(
                    f"untrusted_content={has_untrusted} "
                    f"sensitive_data={has_sensitive} "
                    f"internet_access={has_internet}"
                ),
                remediation=(
                    "Split these capabilities across separate servers with strict "
                    "trust boundaries. Use human-in-the-loop approval for any tool "
                    "chain that combines external content with sensitive data access."
                ),
                owasp_code="ASI02",
            ))

    return findings


# ---------------------------------------------------------------------------
# Resource Poisoning Checks (RES001-RES002)
# ---------------------------------------------------------------------------

_SUSPICIOUS_RESOURCE_URIS = [
    re.compile(r"^https?://(localhost|127\.0\.0\.1|0\.0\.0\.0|169\.254\.169\.254)", re.I),
    re.compile(r"^https?://(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.)", re.I),
    re.compile(r"^file://", re.I),
    re.compile(r"^data:", re.I),
    re.compile(r"\.\./"),  # Path traversal
]

_SUSPICIOUS_RESOURCE_TYPES = re.compile(
    r"\b(executable|binary|script|shell|batch|powershell|cmd|bash)\b",
    re.I,
)


def check_resource_poisoning(server: MCPServer) -> list:
    """Detect resource poisoning risks in MCP server configurations."""
    findings = []

    for i, arg in enumerate(server.args):
        if not isinstance(arg, str):
            continue
        for pattern in _SUSPICIOUS_RESOURCE_URIS:
            if pattern.search(arg):
                findings.append(Finding(
                    check_id="RES001",
                    severity=Severity.HIGH,
                    title=f"Suspicious resource URI in args[{i}]",
                    description=(
                        f"Server '{server.name}' has a suspicious resource URI "
                        f"in args[{i}]: '{arg}'. This could be an internal network "
                        "address, file URI, or path traversal attempt that might "
                        "expose sensitive resources or enable SSRF."
                    ),
                    server=server.name,
                    evidence=f"args[{i}]={arg}",
                    remediation="Verify the resource URI is intentional. Use allowlists for resource URIs.",
                    owasp_code="ASI02",
                ))
                break

    for tool in server.tools:
        if not isinstance(tool, dict):
            continue
        tool_name = tool.get("name", "")
        tool_desc = tool.get("description", "")
        if _SUSPICIOUS_RESOURCE_TYPES.search(tool_desc):
            findings.append(Finding(
                check_id="RES002",
                severity=Severity.MEDIUM,
                title=f"Suspicious resource type in tool '{tool_name}'",
                description=(
                    f"Tool '{tool_name}' on server '{server.name}' references "
                    "executable/script resource types. This could be used to "
                    "poison the LLM context with malicious instructions disguised "
                    "as resource content."
                ),
                server=server.name,
                tool=tool_name,
                evidence=f"description={tool_desc[:100]}",
                remediation="Verify the resource type is legitimate. Consider restricting resource types to safe formats (text, json).",
                owasp_code="ASI06",
            ))

    return findings


# ---------------------------------------------------------------------------
# Prompt Template Poisoning Checks (PTM001-PTM002)
# ---------------------------------------------------------------------------

_PROMPT_MANIPULATION = re.compile(
    r"\b(system prompt|system_prompt|systemPrompt|"
    r"internal instructions|internal_instructions|"
    r"hidden instructions|hiddenInstructions|"
    r"developer message|developerMessage)\b",
    re.I,
)

_PROMPT_EXFILTRATION = re.compile(
    r"\b(reveal|expose|show|display|print|output|return|send|exfil)\s+"
    r"(?:\w+\s+){0,3}(system|internal|hidden|developer|secret)\s*(prompt|instruction|message)",
    re.I,
)


def check_prompt_template_poisoning(server: MCPServer) -> list:
    """Detect prompt template poisoning risks."""
    findings = []

    for tool in server.tools:
        if not isinstance(tool, dict):
            continue
        tool_name = tool.get("name", "")
        tool_desc = tool.get("description", "")
        combined = f"{tool_name} {tool_desc}"

        if _PROMPT_MANIPULATION.search(combined):
            findings.append(Finding(
                check_id="PTM001",
                severity=Severity.HIGH,
                title=f"Prompt template manipulation in tool '{tool_name}'",
                description=(
                    f"Tool '{tool_name}' on server '{server.name}' references "
                    "system prompts or internal instructions. This could be used "
                    "to manipulate the agent's behavior by injecting instructions "
                    "through prompt templates."
                ),
                server=server.name,
                tool=tool_name,
                evidence=f"description={tool_desc[:100]}",
                remediation="Verify the tool's access to system prompts is intentional. Consider restricting prompt template access to trusted servers only.",
                owasp_code="ASI06",
            ))

        if _PROMPT_EXFILTRATION.search(combined):
            findings.append(Finding(
                check_id="PTM002",
                severity=Severity.CRITICAL,
                title=f"Prompt template exfiltration in tool '{tool_name}'",
                description=(
                    f"Tool '{tool_name}' on server '{server.name}' appears designed "
                    "to exfiltrate system prompts or internal instructions. This is "
                    "a direct prompt injection attack vector."
                ),
                server=server.name,
                tool=tool_name,
                evidence=f"description={tool_desc[:100]}",
                remediation="Remove this tool or restrict it to read-only access. Never allow tools to exfiltrate system prompts.",
                owasp_code="ASI06",
            ))

    return findings


# ---------------------------------------------------------------------------
# System Prompt Leakage Check (SPL001)
# ---------------------------------------------------------------------------

def check_system_prompt_leakage(server: MCPServer) -> list:
    """Detect tools that might expose system prompts (OWASP ASI08)."""
    findings = []

    leakage_patterns = re.compile(
        r"\b(system prompt|system_prompt|systemPrompt|"
        r"your instructions|your programming|your guidelines|"
        r"what you are|who you are|your rules|your constraints)\b",
        re.I,
    )

    for tool in server.tools:
        if not isinstance(tool, dict):
            continue
        tool_name = tool.get("name", "")
        tool_desc = tool.get("description", "")

        if leakage_patterns.search(tool_desc):
            findings.append(Finding(
                check_id="SPL001",
                severity=Severity.HIGH,
                title=f"Potential system prompt leakage via tool '{tool_name}'",
                description=(
                    f"Tool '{tool_name}' on server '{server.name}' references "
                    "system prompts or agent instructions in its description. "
                    "This could be used to leak the agent's system prompt to "
                    "an external destination."
                ),
                server=server.name,
                tool=tool_name,
                evidence=f"description={tool_desc[:100]}",
                remediation="Remove references to system prompts from tool descriptions. Treat system prompts as confidential.",
                owasp_code="ASI08",
            ))

    return findings


# ---------------------------------------------------------------------------
# Output Sanitization Check (OUT001)
# ---------------------------------------------------------------------------

def check_output_sanitization(server: MCPServer) -> list:
    """Detect tools that return raw/unsanitized content (OWASP ASI06)."""
    findings = []

    unsanitized_patterns = re.compile(
        r"\b(raw html|raw_html|unescaped|unsanitized|"
        r"as html|as_html|render html|render_html|"
        r"inline html|inline_html|html content)\b",
        re.I,
    )

    for tool in server.tools:
        if not isinstance(tool, dict):
            continue
        tool_name = tool.get("name", "")
        tool_desc = tool.get("description", "")

        if unsanitized_patterns.search(tool_desc):
            findings.append(Finding(
                check_id="OUT001",
                severity=Severity.MEDIUM,
                title=f"Tool '{tool_name}' may return unsanitized content",
                description=(
                    f"Tool '{tool_name}' on server '{server.name}' may return "
                    "raw or unsanitized content. If this content is injected "
                    "into the LLM context without sanitization, it could contain "
                    "embedded prompt injection payloads."
                ),
                server=server.name,
                tool=tool_name,
                evidence=f"description={tool_desc[:100]}",
                remediation="Sanitize all tool outputs before injecting into LLM context. Treat tool responses as untrusted data.",
                owasp_code="ASI06",
            ))

    return findings


# ---------------------------------------------------------------------------
# Rug Pull Detection (RUG001)
# ---------------------------------------------------------------------------

def compute_tool_hash(server: MCPServer) -> str:
    """Compute a SHA-256 hash of all tool definitions for rug pull detection."""
    tool_data = []
    for tool in sorted(server.tools, key=lambda t: t.get("name", "") if isinstance(t, dict) else ""):
        if isinstance(tool, dict):
            tool_data.append(f"{tool.get('name', '')}:{tool.get('description', '')}")
    content = "|".join(tool_data)
    return hashlib.sha256(content.encode()).hexdigest()


def check_rug_pull(server: MCPServer) -> list:
    """Detect potential rug pull risks (post-installation tool changes)."""
    findings = []

    tools_with_desc = [t for t in server.tools if isinstance(t, dict) and t.get("description")]

    if tools_with_desc:
        tool_hash = compute_tool_hash(server)
        findings.append(Finding(
            check_id="RUG001",
            severity=Severity.INFO,
            title=f"Tool definition hash for server '{server.name}'",
            description=(
                f"Server '{server.name}' has {len(tools_with_desc)} tool(s) with "
                "descriptions. The SHA-256 hash of the current tool definitions is "
                "provided below. Store this hash and compare it on subsequent scans "
                "to detect rug pull attacks (post-installation tool changes)."
            ),
            server=server.name,
            evidence=f"tool_hash=sha256:{tool_hash}",
            remediation=(
                "Store this hash and compare on future scans. "
                "If the hash changes, the server's tool definitions have been modified "
                "since the last scan — investigate before continuing to use."
            ),
            owasp_code="ASI06",
        ))

    return findings


# ---------------------------------------------------------------------------
# v2 Check Runner
# ---------------------------------------------------------------------------

def run_v2_checks(servers: list) -> list:
    """Run all v2 security checks on a list of servers."""
    findings = []

    for server in servers:
        findings.extend(check_supply_chain(server))
        findings.extend(check_resource_poisoning(server))
        findings.extend(check_prompt_template_poisoning(server))
        findings.extend(check_system_prompt_leakage(server))
        findings.extend(check_output_sanitization(server))
        findings.extend(check_rug_pull(server))

    # Multi-server checks
    findings.extend(check_toxic_flow(servers))

    findings.sort(key=lambda f: f.severity)
    return findings
