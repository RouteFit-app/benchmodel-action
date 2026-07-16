# BenchModel MCP Config Scan — GitHub Action

Fails a pull request when someone commits a dangerous MCP server config.

It's the same check as [benchmodel.io/mcp-audit](https://benchmodel.io/mcp-audit), running in your
CI instead of a browser tab.

## Nothing leaves your runner

No API key, no token, no account, no network call. The scan is plain static analysis that runs
inside your own job.

That's not a feature, it's a requirement: MCP configs routinely contain live provider keys (this
scanner exists partly to find them), so a checker that uploaded your config somewhere to tell you
it has secrets in it would be self-defeating. Yours never leave.

## Why this exists

In April 2026, OX Security disclosed that config values in the official Anthropic MCP SDKs
(Python, TypeScript, Java, Rust) flow into command execution through the STDIO transport: 14 CVEs,
~150M downloads affected, ~200k exposed instances. Anthropic's position is that the behavior is
by design and sanitization is the developer's responsibility, so **no patch is coming.**

When there's no upstream fix, your config *is* the control. This checks it on every PR.

## Usage

```yaml
name: MCP config scan
on:
  pull_request:

permissions:
  contents: read          # to read the configs
  pull-requests: write    # to post the comment (drop if comment: false)

jobs:
  mcp-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4        # REQUIRED: this action reads files from the repo
      - uses: RouteFit-app/benchmodel-action/mcp-scan@main
        with:
          fail-on: high
```

**`actions/checkout` is required.** This action scans files on disk, so without a checkout there's
nothing to look at and it will find no configs (and pass).

**On `@main`:** there's no `v1` tag covering this action yet, so `@main` is what works today.
It's also unpinned, which is the exact thing `unpinned_package` above flags, and the criticism
lands the same way here: `@main` means you run whatever we pushed last. If that bothers you, and
it reasonably might, pin the SHA instead:
`RouteFit-app/benchmodel-action/mcp-scan@<commit-sha>`. A tagged release is coming.

## Inputs

| input | default | description |
|---|---|---|
| `paths` | *(auto-discover)* | Space-separated config files. Default looks for `.mcp.json`, `mcp.json`, `.cursor/mcp.json`, `.vscode/mcp.json`, `.claude/mcp.json`, `claude_desktop_config.json`, `**/*.mcp.json`. |
| `fail-on` | `high` | Fail the check at this severity or above: `high`, `medium`, or `none` (comment only). There is deliberately no `low`: advisory findings are reported, never blocking. |
| `comment` | `true` | Post results as a PR comment. Needs `pull-requests: write`. |
| `github-token` | `${{ github.token }}` | Token used to post the comment. The default is fine. |

A repo with no MCP configs passes silently. It will never fail a build for not having one.

## What it checks

**Command execution (the OX vector)**

| rule | severity | what it means |
|---|---|---|
| `stdio_shell_command` | high | The server launches via a shell, so every arg is a command. |
| `stdio_shell_metachar` | high | Shell metacharacters (`;` `\|` `&&` `$(`) chain or redirect commands. |
| `stdio_interpolation_to_exec` | medium | `$VAR` / `${VAR}` interpolated into something that executes. The core OX vector. |

**Container isolation turned off**

| rule | severity | what it means |
|---|---|---|
| `container_privileged` | high | `--privileged` or `--cap-add=SYS_ADMIN`. Escaping to the host from there is a one-liner. |
| `container_host_root_mount` | high | `-v /:/...`. The server can read and write every file on the machine. |
| `docker_socket_exposed` | high | The Docker socket is reachable. That is root on the host via the documented API. |
| `container_host_namespace` | medium | `--net`/`--pid`/`--ipc=host`. Reaches localhost-bound services; exposes every process. |
| `container_unconfined` | medium | `seccomp`/`apparmor=unconfined`. Turns off the syscall filter that blocks escapes. |

**PowerShell**

| rule | severity | what it means |
|---|---|---|
| `powershell_policy_bypass` | high | `-ExecutionPolicy Bypass`. Explicitly disables the script-signing check. |
| `powershell_encoded_command` | high | base64 `-EncodedCommand`. A launcher has no reason to be unreadable. |
| `powershell_hidden_window` | medium | `-WindowStyle Hidden`. Whatever it does happens where you can't see it. |

**Credentials**

| rule | severity | what it means |
|---|---|---|
| `plaintext_secret_in_env` | high | A provider key hardcoded in the config (and therefore in git history). |
| `credentials_in_connection_uri` | high | A password inline in a `postgres://`/`mongodb://`/etc connection string. |
| `sensitive_host_path` | medium | Points the server at `~/.ssh`, `~/.aws/credentials`, `~/.kube/config`, `/etc/shadow`. |

**Supply chain and transport**

| rule | severity | what it means |
|---|---|---|
| `tool_description_injection` | high | Imperative text in a tool description. Descriptions are fed to the model as trusted context. |
| `package_from_remote_source` | high | Package installed from a URL/git source, no provenance. |
| `insecure_transport` | medium | `http://` MCP endpoint: tool definitions rewritable in transit. |
| `unpinned_package` | low | `npx`/`uvx`/`pip` with no version pin: every start fetches latest. |
| `auto_confirm_install` | low | `-y`/`--force` auto-confirms fetch-and-execute. |

### Why the two `npx` rules are `low`

`npx -y @scope/server-x` is what the official MCP quickstart tells you to write, so
these two fire on nearly every config that exists. They are still real: if a package
ever ships a bad release, every unpinned config runs it at next start with whatever
is in `env`, which for the official GitHub server is a personal access token.

But an unpinned dependency is a **latent** risk, not a present defect. Nothing is
compromised today; a bad release has to ship first. That's a `low`, and `low` never
fails the check at any `fail-on` setting, including `medium`. You'll see them in the
comment. They will not turn your build red.

We didn't demote them because the finding is unpopular. We demoted them because
"latent" and "present" are different things, and a scanner that inflates one into the
other to look thorough is the kind you learn to ignore.

## What it deliberately does NOT flag

The false-positive rate is the product. A scanner that fires on a normal config gets
uninstalled, so several obvious-looking rules are left out on purpose:

- **`python` / `node` / interpreters with arbitrary args.** Most legitimate MCP servers
  *are* `python -m my_server` or `node server.js`. Flagging them would fire on nearly
  every honest config. Only actual *shells* are flagged, which is the defensible subset.
- **`/tmp` and `/dev/shm`.** Used constantly and legitimately.
- **`-NoProfile` on its own.** Ordinary launchers use it; it means nothing without
  `-EncodedCommand` or a policy bypass alongside it.
- **`/etc` as a whole.** `/etc/ssl/certs` is normal. Only `/etc/shadow`, `/etc/passwd`,
  and `/etc/sudoers` are flagged.
- **`${DB_PASSWORD}` in a connection string, or `postgres://postgres:postgres@localhost`.**
  The first is the *correct* pattern and the second is a local dev default. Flagging the
  right answer is how a scanner loses the room.

Container and PowerShell rules are also gated on the runtime actually being invoked, so
`--privileged` sitting in an unrelated arg cannot fire them.

## Scope, honestly

This checks **configuration patterns**, not the MCP server's implementation. It can't see the
server's source, its dependencies, or what a tool does at runtime. A clean result means "none of
the documented config-level vectors are present," not "you're safe."

It's deterministic: no model, no network, no judgement. The same config always produces the same
findings, and it cannot invent one.

## Run it locally

```bash
python3 mcp-scan/scan.py                     # auto-discover
python3 mcp-scan/scan.py path/to/mcp.json    # explicit
python3 mcp-scan/scan.py --fail-on medium
```

Or paste a config at [benchmodel.io/mcp-audit](https://benchmodel.io/mcp-audit) — that runs in your
browser, same rules, nothing uploaded.
