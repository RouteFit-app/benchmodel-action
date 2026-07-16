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

_INJECTION = [
    "ignore previous", "ignore all previous", "ignore the above", "disregard previous",
    "disregard the above", "system override", "you must always", "you should always",
    "always call", "always run", "before answering, call", "before responding, call",
    "do not tell", "don't tell the user", "without telling", "without informing",
    "do not mention", "never mention", "silently", "secretly",
    "new instructions", "updated instructions", "your real task",
    "actually your task", "override the", "bypass the", "authorized override",
]


def _f(sev, rule, where, detail, fix):
    return {"severity": sev, "rule": rule, "where": where, "detail": detail, "fix": fix}


def _scan_env(name, env, out):
    if not isinstance(env, dict):
        return
    for k, v in env.items():
        if not isinstance(v, str):
            continue
        for pat, label in _SECRETS:
            if pat.search(v):
                out.append(_f("high", "plaintext_secret_in_env", f"{name}.env.{k}",
                              f"A {label} is hardcoded in this config. Anything that reads the file "
                              f"gets the key, and it's now in git history.",
                              "Reference a variable resolved outside the manifest and rotate the key."))
                break


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
        if pkgs and not pinned:
            out.append(_f("medium", "unpinned_package", f"{name}.args",
                          f"{base} runs {pkgs[0]!r} unpinned, so every start fetches whatever is latest.",
                          f"Pin an exact version (e.g. {pkgs[0]}@1.2.3)."))
        if auto and pkgs:
            out.append(_f("medium", "auto_confirm_install", f"{name}.args",
                          f"{auto[0]!r} auto-confirms fetch-and-execute with no prompt.",
                          "Drop the auto-confirm flag or pre-install the pinned package."))


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

    if a.format == "markdown":
        print("## 🛡️ BenchModel MCP config scan\n")
        print(f"Scanned **{scanned}** config file(s). "
              f"**{len(highs)} high**, **{len(meds)} medium**.\n")
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
        print(f"Scanned {scanned} config file(s): {len(highs)} high, {len(meds)} medium.")
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
