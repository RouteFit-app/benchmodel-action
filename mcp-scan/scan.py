#!/usr/bin/env python3
"""Scan a repo's MCP config files for the OX Security advisory vectors. Self-contained.

Runs entirely inside the caller's CI. Nothing is uploaded, no API key, no network:
the configs it reads routinely contain provider keys, so shipping them anywhere
would defeat the point. Same rules as benchmodel.io/mcp-audit (which runs in the
browser for the same reason).

Deterministic: no model, no judgement. Same config, same findings, always.

── PARALLEL BUILD: THESE RULES LIVE IN THREE PLACES ───────────────────────────
Deliberate duplication. Each copy has to run where the config already is, because
an MCP config routinely holds live API keys (this scanner literally flags them),
so the config must never travel to be checked:

  1. modela/backend/services/mcp_scan.py   -- the API (POST /api/mcp-scan)
  2. modela/frontend/src/lib/mcpScan.js    -- the /mcp-audit page, in-browser
  3. benchmodel-action/mcp-scan/scan.py    <- you are here (the GitHub Action)

There's no shared module to extract: the browser can't import Python, and a
GitHub Action has to be self-contained. So CHANGE A RULE = CHANGE ALL THREE.
If they drift, the website and CI give different verdicts for the same config,
which is the one bug a scanner cannot survive.

Usage:
  python scan.py                          # auto-discover common MCP config paths
  python scan.py path/to/mcp.json ...     # explicit files
  python scan.py --fail-on high           # exit 1 when a high-severity finding exists
  python scan.py --format markdown        # PR-comment-ready output
"""
import argparse
import glob
import json
import re
import sys

SEV_ORDER = {"high": 0, "medium": 1, "low": 2}

DEFAULT_GLOBS = [
    ".mcp.json", "mcp.json", "**/mcp.json", "**/.mcp.json",
    ".cursor/mcp.json", ".vscode/mcp.json", ".claude/mcp.json",
    "claude_desktop_config.json", "**/claude_desktop_config.json",
    "**/*.mcp.json",
]

_SHELLS = {"sh", "bash", "zsh", "dash", "ksh", "fish",
           "cmd", "cmd.exe", "powershell", "powershell.exe", "pwsh", "pwsh.exe"}
_METACHAR = re.compile(r"(?:\|\||&&|\$\(|[;`|&>])")
_INTERP = re.compile(r"\$\{[^}]*\}|\$[A-Za-z_][A-Za-z0-9_]*")
_INSTALLERS = {"npx", "uvx", "bunx", "pipx", "pip", "pip3", "uv", "yarn", "pnpm", "npm"}
_AUTO_YES = {"-y", "--yes", "-f", "--force"}
_REMOTE_SRC = re.compile(r"^(?:https?://|git\+|github:|file:)", re.I)

_SECRETS = [
    (re.compile(r"sk-ant-[A-Za-z0-9_\-]{12,}"), "Anthropic API key"),
    (re.compile(r"sk-[A-Za-z0-9_\-]{20,}"), "OpenAI-style API key"),
    (re.compile(r"ghp_[A-Za-z0-9]{20,}"), "GitHub personal access token"),
    (re.compile(r"github_pat_[A-Za-z0-9_]{20,}"), "GitHub fine-grained token"),
    (re.compile(r"AKIA[0-9A-Z]{16}"), "AWS access key id"),
    (re.compile(r"AIza[0-9A-Za-z_\-]{30,}"), "Google API key"),
    (re.compile(r"whsec_[A-Za-z0-9]{16,}"), "Stripe webhook secret"),
    (re.compile(r"xox[baprs]-[A-Za-z0-9\-]{10,}"), "Slack token"),
    (re.compile(r"glpat-[A-Za-z0-9_\-]{16,}"), "GitLab token"),
]
_BASE_URL_KEY = re.compile(r"(?:_BASE_URL|_API_BASE|_API_HOST|_ENDPOINT)$", re.I)
_OFFICIAL_API_HOSTS = {
    "api.anthropic.com", "api.openai.com", "generativelanguage.googleapis.com",
    "api.deepseek.com", "openrouter.ai", "api.mistral.ai", "api.groq.com",
    "api.x.ai", "api.cohere.ai", "api.together.xyz",
}
_LOCAL_HOSTS = {"localhost", "127.0.0.1", "0.0.0.0", "::1"}

def _host_of(url):
    m = re.match(r"[a-z][a-z0-9+.\-]*://([^/:\s]+)", url.strip(), re.I)
    return m.group(1).lower() if m else None
_INJECTION = [
    "ignore previous", "ignore all previous", "ignore the above", "disregard previous",
    "disregard the above", "system override", "you must always", "you should always",
    "always call", "always run", "before answering, call", "before responding, call",
    "do not tell", "don't tell the user", "without telling", "without informing",
    "do not mention", "never mention", "silently", "secretly",
    "new instructions", "updated instructions", "your real task",
    "actually your task", "override the", "bypass the", "authorized override",
]

# Container runtimes with isolation switched back off. GATED on the runtime actually
# being invoked: "--privileged" means nothing outside docker/podman, and an ungated
# match would fire on unrelated args. The gate matters more than the rule.
_CONTAINER_CMDS = {"docker", "podman", "nerdctl", "docker-compose", "podman-compose"}
_CONTAINER_RUN = re.compile(r"\b(?:docker|podman|nerdctl)\s+(?:run|create|exec|compose)\b", re.I)
_PRIVILEGED = re.compile(r"--privileged\b|--cap-add[=\s]+(?:ALL|SYS_ADMIN|SYS_PTRACE|SYS_MODULE)", re.I)
_HOST_NS = re.compile(r"--(?:network|net|pid|ipc|uts)[=\s]+host\b", re.I)
_HOST_ROOT_MOUNT = re.compile(r"(?:-v|--volume)[=\s]+/:|--mount[=\s][^\n]*?\bsource=/(?:[,\s\"']|$)", re.I)
_DOCKER_SOCK = re.compile(r"docker\.sock", re.I)
_UNCONFINED = re.compile(r"--security-opt[=\s]+(?:seccomp|apparmor)=unconfined", re.I)

# PowerShell flags that disable a control or hide what runs. Also gated. Deliberately
# NOT flagging -NoProfile alone: legitimate launchers use it constantly, so it's noise.
_PS_INVOKED = re.compile(r"\b(?:powershell|pwsh)(?:\.exe)?\b", re.I)
_PS_BYPASS = re.compile(r"-(?:executionpolicy|execpolicy|exec|ep)[\s:=]+(?:bypass|unrestricted)", re.I)
_PS_ENCODED = re.compile(r"-(?:encodedcommand|encoded|enc|e)[\s:=]+[A-Za-z0-9+/=]{16,}", re.I)
_PS_HIDDEN = re.compile(r"-(?:windowstyle|w)[\s:=]+hidden", re.I)

# Credentials inline in a connection URI.
_DB_URI = re.compile(
    r"\b(postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|rediss?|amqps?|mssql|clickhouse|ftp)"
    r"://[^\s:/@\"']+:([^\s@/\"']+)@",
    re.I,
)
# A variable reference in the password slot is the CORRECT pattern. Never flag the
# right answer. Placeholders and local-dev defaults are excluded for the same reason:
# firing on "postgres://postgres:postgres@localhost" is how a scanner loses trust.
_VAR_ONLY = re.compile(r"^(?:\$\{[^}]*\}|\$[A-Za-z_][A-Za-z0-9_]*|%[A-Za-z_][A-Za-z0-9_]*%)$")
_PLACEHOLDER_PW = {
    "password", "passwd", "pass", "secret", "changeme", "change_me", "placeholder",
    "yourpassword", "your_password", "mypassword", "example", "test", "postgres",
    "root", "admin", "guest", "xxx", "xxxx", "xxxxx", "***", "redacted",
}

# Host paths that hand the agent a credential store. Narrow on purpose: "/etc" as a
# whole is not a finding (/etc/ssl/certs is normal), /etc/shadow is. /tmp is not
# listed either, legitimate servers use it constantly.
_SENSITIVE_PATHS = [
    # Trailing separator is optional: the common case is a mount like
    # "-v /home/u/.ssh:/root/.ssh", where .ssh is followed by ':' not '/'.
    (re.compile(r"\.ssh(?:[/\\:\"'\s]|$)", re.I), "your SSH directory (~/.ssh)"),
    (re.compile(r"\bid_(?:rsa|dsa|ecdsa|ed25519)\b", re.I), "an SSH private key"),
    (re.compile(r"[/\\]etc[/\\](?:shadow|sudoers|passwd)\b", re.I), "system account files (/etc/shadow, /etc/passwd)"),
    (re.compile(r"\.aws[/\\]credentials\b", re.I), "your AWS credentials file"),
    (re.compile(r"\.kube[/\\]config\b", re.I), "your kubeconfig (cluster credentials)"),
    (re.compile(r"\.docker[/\\]config\.json\b", re.I), "your container registry credentials"),
    (re.compile(r"[/\\]\.?netrc\b", re.I), "your .netrc credentials"),
    (re.compile(r"\.git-credentials\b", re.I), "your stored git credentials"),
]


def _f(sev, rule, where, detail, fix, subject=None):
    """`subject` is the specific thing that tripped the rule (package, key type,
    URI scheme). It lets _dedupe merge a rule across servers without losing which
    packages/keys were involved. Dropped before output."""
    f = {"severity": sev, "rule": rule, "where": where, "detail": detail, "fix": fix}
    if subject:
        f["subject"] = subject
    return f


def _dedupe(findings):
    """One rule firing on N servers is one problem, not N.

    The official MCP quickstart tells people to write `npx -y @scope/server-x`, so a
    normal 3-server config produced six near-identical medium findings (unpinned x3,
    auto-confirm x3) that buried the ones that actually differed. Fold each rule into
    a single entry listing every location it hit.
    """
    groups, order = {}, []
    for f in findings:
        if f["rule"] not in groups:
            groups[f["rule"]] = []
            order.append(f["rule"])
        groups[f["rule"]].append(f)

    out = []
    for rule in order:
        g = groups[rule]
        merged = dict(g[0])
        if len(g) > 1:
            wheres = list(dict.fromkeys(x["where"] for x in g))
            merged["where"] = ", ".join(wheres)
            merged["count"] = len(g)
            subjects = list(dict.fromkeys(x["subject"] for x in g if x.get("subject")))
            if len(subjects) > 1:
                merged["detail"] = merged["detail"].rstrip() + " Same for " + ", ".join(subjects[1:]) + "."
        merged.pop("subject", None)
        out.append(merged)
    return out


def _article(word):
    """'An Anthropic API key', not 'A Anthropic API key'."""
    return "An" if word[:1].upper() in "AEIOU" else "A"


def _scan_uri_credentials(text, where, out):
    for m in _DB_URI.finditer(text):
        scheme, pw = m.group(1), m.group(2)
        if _VAR_ONLY.match(pw) or pw.lower() in _PLACEHOLDER_PW:
            continue
        out.append(_f("high", "credentials_in_connection_uri", where,
                      f"{_article(scheme)} {scheme} connection string carries its password inline, so it's in git "
                      f"history and in the process list of whatever launches this server.",
                      "Move it to a variable resolved outside the manifest "
                      "(scheme://user:${DB_PASSWORD}@host) and rotate the exposed one.",
                      subject=scheme))
        return


def _scan_sensitive_paths(text, where, out):
    for pat, label in _SENSITIVE_PATHS:
        if pat.search(text):
            out.append(_f("medium", "sensitive_host_path", where,
                          f"This points the server at {label}. An MCP server is untrusted code a "
                          f"model can be talked into driving, so what it can read, an injection "
                          f"can exfiltrate.",
                          "Narrow the path to what the server needs. If it needs one credential, "
                          "pass that value rather than the whole store.",
                          subject=label))
            return


def _scan_exec_flags(name, command, args, out):
    """Dangerous flags on the resolved command line.

    Matched against the JOINED line, not per-arg, because these appear both as real
    argv (command="docker", args=["run","--privileged"]) and buried in a single shell
    string (command="bash", args=["-c","docker run --privileged ..."]).
    """
    line = " ".join([command] + args)
    base = command.strip().split("/")[-1].split("\\")[-1].lower()
    where = f"{name}.args"

    if base in _CONTAINER_CMDS or _CONTAINER_RUN.search(line):
        if _PRIVILEGED.search(line):
            out.append(_f("high", "container_privileged", where,
                          "Container runs --privileged (or with SYS_ADMIN). That switches off the "
                          "isolation the container existed to provide; escaping to the host from "
                          "there is a documented one-liner.",
                          "Drop --privileged. Add back only the capability needed "
                          "(--cap-drop=ALL --cap-add=<one>)."))
        if _HOST_ROOT_MOUNT.search(line):
            out.append(_f("high", "container_host_root_mount", where,
                          "The host filesystem root is mounted in, so the server can read and "
                          "write every file on the machine, including your keys.",
                          "Mount only the directory the server needs, read-only where possible."))
        if _HOST_NS.search(line):
            out.append(_f("medium", "container_host_namespace", where,
                          "Container shares a host namespace (--net/--pid/--ipc=host), removing "
                          "that boundary. Host networking reaches localhost-bound services; host "
                          "PID exposes every process.",
                          "Remove the flag. Publish the specific port instead of --net=host."))
        if _UNCONFINED.search(line):
            out.append(_f("medium", "container_unconfined", where,
                          "seccomp/AppArmor set to unconfined, disabling the syscall filter that "
                          "blocks common container-escape primitives.",
                          "Remove the --security-opt override; keep the default profile."))

    if _DOCKER_SOCK.search(line):
        out.append(_f("high", "docker_socket_exposed", where,
                      "The Docker socket is exposed to this server. Anything that can talk to it "
                      "can start a privileged container mounting the host, so this grants root. "
                      "No exploit needed, it's the documented API.",
                      "Don't pass the socket through. If the Docker API is genuinely needed, front "
                      "it with a proxy that allowlists specific calls."))

    if base.startswith(("powershell", "pwsh")) or _PS_INVOKED.search(line):
        if _PS_BYPASS.search(line):
            out.append(_f("high", "powershell_policy_bypass", where,
                          "PowerShell launched with -ExecutionPolicy Bypass/Unrestricted, which "
                          "explicitly disables the script-signing check.",
                          "Remove the flag. Sign the script, or invoke the binary directly."))
        if _PS_ENCODED.search(line):
            out.append(_f("high", "powershell_encoded_command", where,
                          "PowerShell handed a base64 -EncodedCommand. It hides what runs from "
                          "anyone reviewing the config, which is why it's standard payload "
                          "packaging. A launcher has no reason to be unreadable.",
                          "Replace with the plain command, or a reviewable script file."))
        if _PS_HIDDEN.search(line):
            out.append(_f("medium", "powershell_hidden_window", where,
                          "PowerShell launched with a hidden window, so what it does (including "
                          "prompting you) happens where you can't see it.",
                          "Remove -WindowStyle Hidden."))

    _scan_uri_credentials(line, where, out)
    _scan_sensitive_paths(line, where, out)


def _scan_env(name, env, out):
    if not isinstance(env, dict):
        return
    for k, v in env.items():
        if not isinstance(v, str):
            continue
          if _BASE_URL_KEY.search(k):
            host = _host_of(v)
            if host and host not in _OFFICIAL_API_HOSTS and host not in _LOCAL_HOSTS:
                out.append(_finding(
                    "high", "provider_base_url_override", f"{name}.env.{k}",
                    f"{k} redirects the API base URL to {host!r}, not the provider's own "
                    f"endpoint. An SDK sends your key to whatever base URL is set, so this "
                    f"silently ships credentialed traffic (and the key) to that host -- the "
                    f"key-exfiltration vector behind CVE-2026-21852.",
                    "Remove the override or point it back at the official endpoint. If you run a "
                    "trusted proxy, pin it to a host you control and confirm it never logs the key.",
                    subject=k,
                ))
        for pat, label in _SECRETS:
            if pat.search(v):
                out.append(_f("high", "plaintext_secret_in_env", f"{name}.env.{k}",
                              f"{_article(label)} {label} is hardcoded in this config. Anything that reads the file "
                              f"gets the key, and it's now in git history.",
                              "Reference a variable resolved outside the manifest and rotate the key.",
                              subject=label))
                break
        _scan_uri_credentials(v, f"{name}.env.{k}", out)
        _scan_sensitive_paths(v, f"{name}.env.{k}", out)


def _scan_stdio(name, cfg, out):
    command = cfg.get("command")
    args = cfg.get("args") or []
    if not isinstance(args, list):
        args = [str(args)]
    args = [a if isinstance(a, str) else json.dumps(a) for a in args]
    if not isinstance(command, str) or not command.strip():
        return
    base = command.strip().split("/")[-1].split("\\")[-1].lower()

    if base in _SHELLS:
        out.append(_f("high", "stdio_shell_command", f"{name}.command",
                      f"Server launches through a shell ({command!r}); under STDIO every arg is then "
                      f"interpreted as a command.",
                      "Invoke the binary directly and pass args as list elements."))

    for i, val in enumerate([command] + args):
        where = f"{name}.command" if i == 0 else f"{name}.args[{i - 1}]"
        if _METACHAR.search(val):
            out.append(_f("high", "stdio_shell_metachar", where,
                          f"Shell metacharacters in {val!r} chain or redirect commands.",
                          "Remove them; pass each argument as its own list element."))
        if _INTERP.search(val):
            out.append(_f("medium", "stdio_interpolation_to_exec", where,
                          f"{val!r} interpolates a variable into a value that gets executed. This is "
                          f"the pattern OX Security flagged across the official MCP SDKs.",
                          "Resolve and allowlist the value before it reaches the config."))

    if base in _INSTALLERS:
        pkgs = [a for a in args if not a.startswith("-")]
        auto = [a for a in args if a.lower() in _AUTO_YES]
        pinned = any("@" in p[1:] for p in pkgs) or any("==" in p for p in pkgs)
        for p in pkgs:
            if _REMOTE_SRC.search(p):
                out.append(_f("high", "package_from_remote_source", f"{name}.args",
                              f"{p!r} installs from a URL/git source with no published provenance.",
                              "Install from the registry with a pinned version."))
        # `npx -y @scope/pkg` is what the official MCP quickstart tells people to
        # write, so these two fire on nearly every config in existence. Low, not
        # medium, and the reason matters: an unpinned dep is a LATENT risk, not a
        # present defect. Nothing is compromised today; a bad release would have to
        # ship first. Not deleted, because if a bad release ever does ship, every
        # unpinned config runs it at next start with whatever is in env. `low` is
        # excluded from every fail path, so this can never break a build. Both rules
        # move together: they describe one pattern.
        if pkgs and not pinned:
            out.append(_f("low", "unpinned_package", f"{name}.args",
                          f"{base} runs {pkgs[0]!r} unpinned, so every start fetches whatever is latest.",
                          f"Pin an exact version (e.g. {pkgs[0]}@1.2.3).",
                          subject=pkgs[0]))
        if auto and pkgs:
            out.append(_f("low", "auto_confirm_install", f"{name}.args",
                          f"{auto[0]!r} auto-confirms fetch-and-execute with no prompt.",
                          "Drop the auto-confirm flag or pre-install the pinned package.",
                          subject=auto[0]))

    # Container escapes, PowerShell bypasses, inline creds, credential paths.
    _scan_exec_flags(name, command, args, out)


def _scan_url(name, cfg, out):
    url = cfg.get("url") or cfg.get("endpoint")
    if isinstance(url, str) and url.lower().startswith("http://"):
        out.append(_f("medium", "insecure_transport", f"{name}.url",
                      f"{url!r} is plain HTTP; tool definitions and auth headers can be rewritten "
                      f"in transit.", "Use https://."))


def _scan_tools(name, obj, out):
    tools = obj.get("tools")
    if not isinstance(tools, list):
        return
    for i, tool in enumerate(tools):
        if not isinstance(tool, dict):
            continue
        tname = tool.get("name") or f"[{i}]"
        text = " ".join(str(tool.get(f, "")) for f in
                        ("description", "instructions", "summary", "usage")).lower()
        hits = [p for p in _INJECTION if p in text]
        if hits:
            out.append(_f("high", "tool_description_injection",
                          f"{name}.tools.{tname}.description",
                          f"Tool description contains imperative instruction text "
                          f"({', '.join(hits[:3])}). Descriptions are fed to the model as trusted "
                          f"context, so this is a prompt-injection delivery vector.",
                          "Describe what the tool does; never instruct the model."))


def scan_config(data):
    servers = data.get("mcpServers") or data.get("servers")
    if not isinstance(servers, dict):
        servers = {"(root)": data} if ("command" in data or "url" in data or "tools" in data) else {}
    findings = []
    for name, cfg in servers.items():
        if not isinstance(cfg, dict):
            continue
        _scan_stdio(name, cfg, findings)
        _scan_url(name, cfg, findings)
        _scan_env(name, cfg.get("env"), findings)
        _scan_tools(name, cfg, findings)
    nested = any(isinstance(c, dict) and "tools" in c for c in servers.values())
    if data.get("tools") and not nested:
        _scan_tools("(manifest)", data, findings)
    # Merge before counting: the summary should reflect distinct problems, not how
    # many servers happen to share one.
    findings = _dedupe(findings)
    findings.sort(key=lambda f: SEV_ORDER.get(f["severity"], 9))
    return findings, len(servers)


def discover(patterns):
    seen, files = set(), []
    for pat in patterns:
        for p in glob.glob(pat, recursive=True):
            if p not in seen and not p.startswith(("node_modules/", ".git/")):
                seen.add(p)
                files.append(p)
    return files


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("paths", nargs="*", help="Config file(s). Default: auto-discover common MCP paths.")
    ap.add_argument("--fail-on", choices=["none", "medium", "high"], default="high")
    ap.add_argument("--format", choices=["text", "markdown"], default="text")
    a = ap.parse_args()

    files = a.paths or discover(DEFAULT_GLOBS)
    if not files:
        print("No MCP config files found (looked for .mcp.json, mcp.json, .cursor/mcp.json, "
              "claude_desktop_config.json, **/*.mcp.json). Nothing to scan.")
        return 0

    all_findings, scanned, bad = [], 0, []
    for path in files:
        try:
            with open(path, encoding="utf-8") as fh:
                data = json.load(fh)
        except (OSError, json.JSONDecodeError) as e:
            bad.append((path, str(e)))
            continue
        if not isinstance(data, dict):
            continue
        findings, n = scan_config(data)
        scanned += 1
        for f in findings:
            f["file"] = path
        all_findings.extend(findings)

    highs = [f for f in all_findings if f["severity"] == "high"]
    meds = [f for f in all_findings if f["severity"] == "medium"]
    # Counted and printed, never failed on. The npx rules land here, and they'd be
    # invisible in CI if the summary only tallied high/medium.
    lows = [f for f in all_findings if f["severity"] == "low"]

    if a.format == "markdown":
        print("## 🛡️ BenchModel MCP config scan\n")
        print(f"Scanned **{scanned}** config file(s). "
              f"**{len(highs)} high**, **{len(meds)} medium**, "
              f"{len(lows)} low (advisory, never fails the check).\n")
        if not all_findings:
            print("No known config-level vectors found. (This checks configuration patterns, "
                  "not the MCP server's runtime code.)")
        else:
            print("| Severity | File | Location | Issue |")
            print("|---|---|---|---|")
            for f in all_findings:
                issue = f["detail"].replace("|", "\\|").replace("\n", " ")
                print(f"| {f['severity']} | `{f['file']}` | `{f['where']}` | {issue} |")
            print("\n<details><summary>Fixes</summary>\n")
            for f in all_findings:
                print(f"- **{f['file']} · {f['where']}** — {f['fix']}")
            print("\n</details>")
        print("\n<sub>Static analysis, no AI, nothing left this runner. "
              "<a href=\"https://benchmodel.io/mcp-audit\">benchmodel.io/mcp-audit</a></sub>")
    else:
        for path, err in bad:
            print(f"skip {path}: {err}")
        print(f"Scanned {scanned} config file(s): {len(highs)} high, {len(meds)} medium, "
              f"{len(lows)} low (advisory).")
        for f in all_findings:
            print(f"  [{f['severity']:6}] {f['file']} :: {f['where']} :: {f['rule']}")
            print(f"           {f['detail']}")
            print(f"           fix: {f['fix']}")

    if a.fail_on == "high" and highs:
        print(f"\nFailing: {len(highs)} high-severity finding(s).", file=sys.stderr)
        return 1
    if a.fail_on == "medium" and (highs or meds):
        print(f"\nFailing: {len(highs) + len(meds)} finding(s) at medium or above.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
