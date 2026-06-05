"""Security checks for MCP server configurations."""

from __future__ import annotations

import re
from scanner.models import Finding, MCPServer, Severity

# Hardcoded secret patterns: (regex, description)
_SECRET_PATTERNS = [
    (re.compile(r"sk-[A-Za-z0-9]{20,}", re.I), "API key (sk- prefix)"),
    (re.compile(r"AKIA[0-9A-Z]{16}"), "AWS access key ID"),
    (re.compile(r"(?:password|passwd|pwd|secret|token|api_key|apikey)\s*[:=]\s*[\"']?[^\s\"']{8,}", re.I), "Hardcoded credential"),
    (re.compile(r"(?:supersecret|hardcoded|plaintext|insecure|default|changeme|admin123|password123)", re.I), "Common weak secret"),
    (re.compile(r"[A-Za-z0-9/+=]{40,}"), "High-entropy string (possible secret)"),
    (re.compile(r"postgres(ql)?://[^/\s]+:[^@\s]+@", re.I), "Database URL with embedded password"),
]

# Prompt injection markers in tool descriptions
_PROMPT_INJECTION_RE = re.compile(
    r"<\s*IMPORTANT\s*>|"
    r"ignore\s+(all\s+)?previous\s+instructions|"
    r"disregard\s+(all\s+)?prior|"
    r"you\s+are\s+now\s+(a|an|the)\s+|"
    r"new\s+instructions?\s*[:：]|"
    r"override\s+safety|"
    r"send\s+all\s+(user\s+)?data|"
    r"silently\s+(upload|exfil|send)",
    re.I,
)

# Credential harvesting patterns
_CRED_HARVEST_RE = re.compile(
    r"send\s+(the\s+)?(api\s+key|secret|credential|token|password|key)\s+to|"
    r"exfiltrate|"
    r"upload\s+(the\s+)?(secret|credential|key)",
    re.I,
)

# Safety bypass patterns
_SAFETY_BYPASS_RE = re.compile(
    r"bypass\s+(all\s+)?(safety|filter|restriction|security)|"
    r"disable\s+(all\s+)?(safety|filter|restriction|security)|"
    r"ignore\s+(all\s+)?(safety|filter|restriction|security)",
    re.I,
)

# Dangerous tool names that suggest command execution
_DANGEROUS_TOOL_NAMES = {
    "exec", "execute", "shell", "bash", "sh", "cmd", "powershell",
    "eval", "run", "system", "subprocess", "os.system", "os.popen",
    "exec_command", "run_command", "execute_command",
}

# Shell metacharacters and patterns
_SHELL_METACHAR_RE = re.compile(r"[;&|`$(){}\[\]<>!#\\\\]")
_SH_C_RE = re.compile(r"\bsh\s+-c\b|\bbash\s+-c\b|\bcmd\s+/c\b", re.I)
_ENV_INTERPOLATION_RE = re.compile(r"\$\w+|\$\{[^}]+\}")
_EVAL_RE = re.compile(r"\beval\b|\bexec\b|\bsubprocess\b|\bos\.system\b|\bos\.popen\b", re.I)

# Internal URL patterns for SSRF detection
_INTERNAL_URL_PATTERNS = [
    re.compile(r"https?://127\.0\.0\.1", re.I),
    re.compile(r"https?://localhost", re.I),
    re.compile(r"https?://169\.254\.169\.254", re.I),
    re.compile(r"https?://10\.\d+\.\d+\.\d+", re.I),
    re.compile(r"https?://172\.(1[6-9]|2\d|3[01])\.\d+\.\d+", re.I),
    re.compile(r"https?://192\.168\.\d+\.\d+", re.I),
    re.compile(r"https?://0\.0\.0\.0", re.I),
    re.compile(r"https?://\[::1\]", re.I),
]

# Dangerous command patterns
_DANGEROUS_COMMANDS = {"sudo", "rm", "chmod", "chown", "mkfs", "dd", "wget", "curl"}


def check_missing_auth(server: MCPServer) -> list:
    """Detect servers without authentication mechanisms."""
    findings = []

    # AUTH001: Remote server without authentication
    if server.transport != "stdio" and server.url:
        if not server.auth:
            auth_keys = {"authorization", "auth_token", "api_key", "token", "bearer", "x-api-key"}
            has_auth_env = any(
                any(ak in k.lower() for ak in auth_keys)
                for k in server.env.keys()
            )
            has_auth_header = any(
                any(ak in k.lower() for ak in auth_keys)
                for k in server.headers.keys()
            )
            url_has_creds = bool(re.search(r"https?://[^:]+:[^@]+@", server.url))

            if not (has_auth_env or has_auth_header or url_has_creds):
                findings.append(Finding(
                    check_id="AUTH001",
                    severity=Severity.HIGH,
                    title=f"Remote server '{server.name}' has no authentication",
                    description=(
                        f"Server '{server.name}' connects to '{server.url}' with no "
                        "authentication headers, tokens, or credentials. Any client can "
                        "connect and invoke tools."
                    ),
                    server=server.name,
                    evidence=f"url={server.url}, headers={list(server.headers.keys())}",
                    remediation=(
                        "Add authentication headers (e.g., Authorization: Bearer *** "
                        "or use environment variable references for secrets."
                    ),
                    owasp_code="ASI01",
                ))

    # AUTH002: Local stdio server with env vars but no auth tokens
    is_local = server.transport == "stdio" or (not server.url and server.command)
    if is_local and not server.auth and server.env:
        auth_keys = {"authorization", "auth_token", "api_key", "token", "bearer", "x-api-key"}
        has_auth_env = any(
            any(ak in k.lower() for ak in auth_keys)
            for k in server.env.keys()
        )
        if not has_auth_env:
            findings.append(Finding(
                check_id="AUTH002",
                severity=Severity.MEDIUM,
                title=f"Local server '{server.name}' has env vars but no auth tokens",
                description=(
                    f"Server '{server.name}' is a local stdio server with "
                    f"{len(server.env)} environment variable(s) but no authentication "
                    "tokens. Any local process can connect and invoke tools."
                ),
                server=server.name,
                evidence=f"env_vars={list(server.env.keys())}",
                remediation=(
                    "Add authentication tokens to environment variables or "
                    "use process-level isolation."
                ),
                owasp_code="ASI01",
            ))

    return findings

def check_hardcoded_secrets(server: MCPServer) -> list:
    """Detect hardcoded secrets in environment variables and args."""
    findings = []

    for key, value in server.env.items():
        if not isinstance(value, str):
            continue
        # Skip environment variable references like ${VAR} or $VAR
        if re.match(r"^\$\{?\w+\}?$", value):
            continue
        for pattern, secret_type in _SECRET_PATTERNS:
            if pattern.search(value):
                findings.append(Finding(
                    check_id="SEC001",
                    severity=Severity.CRITICAL,
                    title=f"Hardcoded {secret_type} in env var '{key}'",
                    description=(
                        f"Server '{server.name}' has a hardcoded {secret_type} "
                        f"in environment variable '{key}'. This secret is exposed "
                        "in the configuration file."
                    ),
                    server=server.name,
                    evidence=f"{key}={value[:20]}...",
                    remediation=(
                        f"Replace the hardcoded value with ${{{key}}} and set "
                        "the actual value in the environment or a secrets manager."
                    ),
                    owasp_code="ASI03",
                ))
                break

    for i, arg in enumerate(server.args):
        if not isinstance(arg, str):
            continue
        for pattern, secret_type in _SECRET_PATTERNS:
            if pattern.search(arg):
                findings.append(Finding(
                    check_id="SEC002",
                    severity=Severity.CRITICAL,
                    title=f"Hardcoded {secret_type} in args[{i}]",
                    description=(
                        f"Server '{server.name}' has a hardcoded {secret_type} "
                        f"in argument {i}. Command-line arguments may be visible "
                        "in process listings and logs."
                    ),
                    server=server.name,
                    evidence=f"args[{i}]={arg[:20]}...",
                    remediation="Use environment variables instead of command-line arguments.",
                    owasp_code="ASI03",
                ))
                break

    # Check URL for embedded tokens
    if server.url:
        token_match = re.search(r"(?:token|key|api_key|secret)=([A-Za-z0-9_\-]{16,})", server.url, re.I)
        if token_match:
            findings.append(Finding(
                check_id="SEC003",
                severity=Severity.CRITICAL,
                title=f"Hardcoded token in URL",
                description=(
                    f"Server '{server.name}' has a hardcoded token in its URL."
                ),
                server=server.name,
                evidence=f"url contains token=...",
                remediation="Use environment variable references for URL tokens.",
                owasp_code="ASI03",
            ))

    return findings


def check_insecure_transport(server: MCPServer) -> list:
    """Detect servers using unencrypted HTTP."""
    findings = []
    if server.url and server.url.startswith("http://"):
        findings.append(Finding(
            check_id="TRANS001",
            severity=Severity.HIGH,
            title=f"Server '{server.name}' uses unencrypted HTTP",
            description=(
                f"Server '{server.name}' connects via '{server.url}'. "
                "Traffic is unencrypted and can be intercepted via MITM attacks."
            ),
            server=server.name,
            evidence=f"url={server.url}",
            remediation="Use HTTPS instead of HTTP for all remote connections.",
            owasp_code="ASI04",
        ))
    return findings


def check_tool_description(server: MCPServer) -> list:
    """Detect prompt injection and malicious patterns in tool descriptions."""
    findings = []

    for tool in server.tools:
        if not isinstance(tool, dict):
            continue
        tool_name = tool.get("name", "")
        description = tool.get("description", "")
        if not isinstance(description, str):
            continue

        # Check for <IMPORTANT> tags and instruction override
        if _PROMPT_INJECTION_RE.search(description):
            findings.append(Finding(
                check_id="TOOL001",
                severity=Severity.CRITICAL,
                title=f"Prompt injection in tool '{tool_name}' description",
                description=(
                    f"Tool '{tool_name}' on server '{server.name}' contains "
                    "prompt injection markers in its description. This could "
                    "manipulate the LLM into executing malicious instructions."
                ),
                server=server.name,
                tool=tool_name,
                evidence=f"description={description[:100]}",
                remediation=(
                    "Remove instruction-override patterns from tool descriptions. "
                    "Descriptions should only describe the tool's function."
                ),
                owasp_code="ASI06",
            ))

        # Check for credential harvesting
        if _CRED_HARVEST_RE.search(description):
            findings.append(Finding(
                check_id="TOOL002",
                severity=Severity.CRITICAL,
                title=f"Credential harvesting pattern in tool '{tool_name}'",
                description=(
                    f"Tool '{tool_name}' on server '{server.name}' description "
                    "contains patterns suggesting credential exfiltration."
                ),
                server=server.name,
                tool=tool_name,
                evidence=f"description={description[:100]}",
                remediation="Remove credential exfiltration patterns from descriptions.",
                owasp_code="ASI06",
            ))

        # Check for safety bypass
        if _SAFETY_BYPASS_RE.search(description):
            findings.append(Finding(
                check_id="TOOL003",
                severity=Severity.HIGH,
                title=f"Safety bypass pattern in tool '{tool_name}'",
                description=(
                    f"Tool '{tool_name}' on server '{server.name}' description "
                    "contains patterns suggesting safety filter bypass."
                ),
                server=server.name,
                tool=tool_name,
                evidence=f"description={description[:100]}",
                remediation="Remove safety bypass patterns from descriptions.",
                owasp_code="ASI06",
            ))

        if tool_name.lower() in _DANGEROUS_TOOL_NAMES:
            findings.append(Finding(
                check_id="TOOL004",
                severity=Severity.MEDIUM,
                title=f"Dangerous tool name '{tool_name}'",
                description=(
                    f"Tool '{tool_name}' on server '{server.name}' has a name "
                    "commonly associated with command execution."
                ),
                server=server.name,
                tool=tool_name,
                evidence=f"tool_name={tool_name}",
                remediation="Use descriptive, specific tool names without implying shell access.",
                owasp_code="ASI06",
            ))

    return findings


def check_tool_shadowing(servers: list) -> list:
    """Detect tool name collisions and shadowing across servers."""
    findings = []
    tool_owners: dict = {}

    for server in servers:
        for tool in server.tools:
            if not isinstance(tool, dict):
                continue
            name = tool.get("name", "")
            if name:
                tool_owners.setdefault(name, []).append(server.name)

    # Check for duplicate tool names across servers
    for tool_name, owners in tool_owners.items():
        if len(owners) > 1:
            findings.append(Finding(
                check_id="SHADOW001",
                severity=Severity.MEDIUM,
                title=f"Tool '{tool_name}' is defined by multiple servers",
                description=(
                    f"Tool '{tool_name}' is defined by {len(owners)} servers: "
                    f"{', '.join(owners)}. The LLM may use the wrong one."
                ),
                server=", ".join(owners),
                tool=tool_name,
                evidence=f"servers={owners}",
                remediation="Ensure tool names are unique across servers.",
                owasp_code="ASI06",
            ))

    return findings


def check_excessive_permissions(server: MCPServer) -> list:
    """Detect servers with excessive filesystem or network permissions."""
    findings = []

    all_args_str = " ".join(str(a) for a in server.args)
    cmd_and_args = f"{server.command} {all_args_str}".strip()

    # Check for broad filesystem access
    for i, arg in enumerate(server.args):
        if not isinstance(arg, str):
            continue
        if arg in ("/", "/root", "/home", "/etc", "/var", "/usr"):
            findings.append(Finding(
                check_id="PERM001",
                severity=Severity.HIGH,
                title=f"Server '{server.name}' has broad filesystem access",
                description=(
                    f"Server '{server.name}' is configured with root path "
                    f"'{arg}' in args[{i}]. This grants access to the entire filesystem."
                ),
                server=server.name,
                evidence=f"args[{i}]={arg}",
                remediation="Restrict filesystem access to the minimum required directory.",
                owasp_code="ASI07",
            ))
            break

    # Check for dangerous commands (sudo, rm -rf, etc.)
    if re.search(r"\bsudo\b", cmd_and_args):
        findings.append(Finding(
            check_id="PERM002",
            severity=Severity.HIGH,
            title=f"Server '{server.name}' uses sudo",
            description=(
                f"Server '{server.name}' command contains sudo: '{cmd_and_args}'. "
                "This grants elevated privileges."
            ),
            server=server.name,
            evidence=f"command={cmd_and_args}",
            remediation="Avoid running MCP servers with elevated privileges.",
            owasp_code="ASI07",
        ))

    if re.search(r"\brm\s+-[rf]", cmd_and_args):
        findings.append(Finding(
            check_id="PERM002",
            severity=Severity.HIGH,
            title=f"Server '{server.name}' uses dangerous rm command",
            description=(
                f"Server '{server.name}' command contains 'rm -rf': '{cmd_and_args}'. "
                "This can delete arbitrary files."
            ),
            server=server.name,
            evidence=f"command={cmd_and_args}",
            remediation="Avoid using rm -rf in MCP server commands.",
            owasp_code="ASI07",
        ))

    # Check for wildcard network binding
    for i, arg in enumerate(server.args):
        if arg in ("0.0.0.0", "::", "*"):
            findings.append(Finding(
                check_id="PERM003",
                severity=Severity.MEDIUM,
                title=f"Server '{server.name}' binds to all interfaces",
                description=(
                    f"Server '{server.name}' binds to '{arg}' in args[{i}]. "
                    "This exposes the server to all network interfaces."
                ),
                server=server.name,
                evidence=f"args[{i}]={arg}",
                remediation="Bind to 127.0.0.1 (localhost) unless external access is required.",
                owasp_code="ASI07",
            ))
            break

    return findings


def check_ssrf_risk(server: MCPServer) -> list:
    """Detect Server-Side Request Forgery risks."""
    findings = []

    for tool in server.tools:
        if not isinstance(tool, dict):
            continue
        tool_name = tool.get("name", "")
        params = tool.get("inputSchema", {}).get("properties", {})
        has_url_param = False
        has_allowlist = False
        for param_name, param_def in params.items():
            if not isinstance(param_def, dict):
                continue
            param_desc = str(param_def.get("description", "")).lower()
            param_type = param_def.get("type", "")
            if param_type == "string" and ("url" in param_name.lower() or "url" in param_desc):
                has_url_param = True
            if "allowed" in param_name.lower() or "allowlist" in param_name.lower():
                has_allowlist = True

        if has_url_param and not has_allowlist:
            findings.append(Finding(
                check_id="SSRF001",
                severity=Severity.HIGH,
                title=f"SSRF risk - '{tool_name}' accepts URLs without allowlist",
                description=(
                    f"Tool '{tool_name}' on server '{server.name}' accepts URL "
                    "parameters but has no allowlist/deny-list parameters."
                ),
                server=server.name,
                tool=tool_name,
                evidence=f"param accepts URL without allowlist",
                remediation="Add URL allowlist or server-side URL validation.",
                owasp_code="ASI02",
            ))

    # Check for internal URLs in args
    for i, arg in enumerate(server.args):
        if not isinstance(arg, str):
            continue
        for pattern in _INTERNAL_URL_PATTERNS:
            if pattern.search(arg):
                findings.append(Finding(
                    check_id="SSRF002",
                    severity=Severity.MEDIUM,
                    title="Internal URL reference in server args",
                    description=(
                        f"Server '{server.name}' references an internal "
                        f"URL in args[{i}]: '{arg}'."
                    ),
                    server=server.name,
                    evidence=f"args[{i}] = {arg}",
                    remediation="Ensure internal URLs are intentional and protected.",
                    owasp_code="ASI02",
                ))
                break

    return findings


def check_command_injection(server: MCPServer) -> list:
    """Detect command injection risks in server configuration."""
    findings = []

    # Combine command + args for full command line analysis
    full_cmd = server.command
    if server.args:
        full_cmd = f"{server.command} {' '.join(str(a) for a in server.args)}"

    # Check for sh -c pattern in command or args
    if _SH_C_RE.search(full_cmd):
        findings.append(Finding(
            check_id="CMD001",
            severity=Severity.CRITICAL,
            title="Shell command injection risk - sh -c pattern",
            description=(
                f"Server '{server.name}' uses 'sh -c' or equivalent: '{full_cmd}'."
            ),
            server=server.name,
            evidence=f"command = {full_cmd}",
            remediation="Avoid shell interpretation. Use direct binary execution.",
            owasp_code="ASI05",
        ))

    # Check for eval/exec patterns
    if _EVAL_RE.search(full_cmd):
        findings.append(Finding(
            check_id="CMD002",
            severity=Severity.CRITICAL,
            title="Dangerous eval/exec pattern in command",
            description=(
                f"Server '{server.name}' command contains eval/exec: '{full_cmd}'."
            ),
            server=server.name,
            evidence=f"command = {full_cmd}",
            remediation="Remove eval/exec patterns. Use safe execution methods.",
            owasp_code="ASI05",
        ))

    # Check for shell metacharacters in args
    for i, arg in enumerate(server.args):
        if not isinstance(arg, str):
            continue
        if _SHELL_METACHAR_RE.search(arg):
            findings.append(Finding(
                check_id="CMD003",
                severity=Severity.HIGH,
                title="Shell metacharacters in server arguments",
                description=(
                    f"Server '{server.name}' args[{i}] contains shell "
                    f"metacharacters: '{arg}'."
                ),
                server=server.name,
                evidence=f"args[{i}] = {arg}",
                remediation="Sanitize arguments. Use parameterized execution.",
                owasp_code="ASI05",
            ))
            break

    # Check tool parameter descriptions for injection
    for tool in server.tools:
        if not isinstance(tool, dict):
            continue
        tool_name = tool.get("name", "")
        params = tool.get("inputSchema", {}).get("properties", {})
        for param_name, param_def in params.items():
            if not isinstance(param_def, dict):
                continue
            param_desc = param_def.get("description", "")
            if isinstance(param_desc, str) and _SHELL_METACHAR_RE.search(param_desc):
                findings.append(Finding(
                    check_id="CMD004",
                    severity=Severity.MEDIUM,
                    title="Shell metacharacters in tool parameter description",
                    description=(
                        f"Tool '{tool_name}' parameter '{param_name}' contains "
                        f"shell metacharacters: '{param_desc[:60]}'."
                    ),
                    server=server.name,
                    tool=tool_name,
                    evidence=f"param '{param_name}' description: {param_desc[:60]}",
                    remediation="Review parameter descriptions for injection patterns.",
                    owasp_code="ASI05",
                ))

    return findings


def run_checks(servers: list) -> list:
    """Run all security checks on a list of servers."""
    findings = []
    for server in servers:
        findings.extend(check_missing_auth(server))
        findings.extend(check_hardcoded_secrets(server))
        findings.extend(check_insecure_transport(server))
        findings.extend(check_tool_description(server))
        findings.extend(check_excessive_permissions(server))
        findings.extend(check_ssrf_risk(server))
        findings.extend(check_command_injection(server))
    findings.extend(check_tool_shadowing(servers))
    findings.sort(key=lambda f: f.severity)
    return findings
