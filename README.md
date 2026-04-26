# Toroidal Detector

Passive security and bug detector for [Claude Code](https://docs.anthropic.com/en/docs/claude-code). Watches every tool call and automatically flags CVEs, vulnerabilities, hardcoded secrets, crashes, and unsafe code patterns. Zero dependencies, zero configuration, zero false-positive noise in your workflow.

Works standalone or as part of the [Torus Framework](https://github.com/OZmasterAI/Torus-Framework).

## How it works

The detector registers as a `PostToolUse` hook in Claude Code. On every tool call, it pattern-matches the output against 150+ signatures across 5 categories:

| Category | Examples | Patterns |
|----------|----------|----------|
| **Security** | CVEs, XSS, SQLi, SSRF, hardcoded secrets, weak crypto, disabled TLS | 35 |
| **Bugs** | Panics, segfaults, data races, deadlocks, null derefs, OOM | 18 |
| **Smart contract** | Reentrancy, unchecked calls, tx.origin, selfdestruct, oracle manipulation | 15 |
| **Economic** | Flash loans, sandwich attacks, price manipulation, governance takeovers | 20 |
| **Code patterns** | Secret keys in source, shell injection, eval/exec with user input, unsafe deserialization | 80+ |

Findings are saved as markdown files in `detected/`, deduplicated by content hash, and auto-committed to git.

## Two modes

### Automated (detector.py)

Runs on every tool call. Catches findings as they happen:

```
detected/
├── bugs/          # panics, segfaults, data races
├── economic/      # flash loans, sandwich attacks
├── errors/        # OOM, resource exhaustion
├── security/      # CVEs, injection, secrets
└── smart-contract/  # reentrancy, tx.origin
```

### Manual (save_finding.py)

For reviewed, confirmed findings with full write-ups:

```bash
echo '{"title":"Auth bypass in login","severity":"high","category":"security","project":"myapp","summary":"...","details":"...","attack_vector":"...","example":"...","impact":"...","remediation":"...","references":"..."}' | python3 save_finding.py
```

Saves to `reviewed/` with structured templates.

## Setup

### Standalone

```bash
git clone https://github.com/OZmasterAI/toroidal-detector.git ~/projects/toroidal-detector
bash ~/projects/toroidal-detector/setup.sh
```

Then add the hook to your Claude Code `settings.json`:

```json
{
  "hooks": {
    "PostToolUse": [
      {
        "type": "command",
        "command": "python3 ~/projects/toroidal-detector/detector.py"
      }
    ]
  }
}
```

### As a submodule

Can be used as a submodule in any project, including [Torus-Framework](https://github.com/OZmasterAI/Torus-Framework):

```bash
git submodule add https://github.com/OZmasterAI/toroidal-detector.git toroidal-detector
```

### Custom location

Set `TOROIDAL_DETECTOR_DIR` to override where findings are stored:

```bash
export TOROIDAL_DETECTOR_DIR=~/my-findings
```

## Language support

Code pattern detection is language-aware. Patterns only fire on relevant file types:

| Language | Extensions |
|----------|-----------|
| Python | `.py`, `.pyw` |
| JavaScript/TypeScript | `.js`, `.jsx`, `.ts`, `.tsx`, `.mjs`, `.cjs`, `.vue`, `.svelte` |
| Go | `.go` |
| Rust | `.rs` |
| C/C++ | `.c`, `.cpp`, `.cc`, `.cxx`, `.h`, `.hpp`, `.hxx` |
| Solidity | `.sol` |

Output-based patterns (CVEs, panics, audit tool results) are language-agnostic.

## How findings are stored

Each finding is a markdown file with YAML frontmatter:

```markdown
---
title: "cve-CVE-2024-1234"
severity: needs-review
category: "security"
project: "myapp"
status: needs-review
date: "2026-04-26"
---

## Auto-Detected Finding
[HIGH] Auto-detected cve in output: CVE-2024-1234

## Source Output
<context around the match>
```

Findings are deduplicated via FNV-1a hash of `pattern:filepath:match`. The same finding won't be recorded twice.

## Works with Toolshed

If you use [Toolshed](https://github.com/OZmasterAI/toroidal-toolshed) as your MCP proxy, the detector also monitors `mcp__toolshed__run_tool` output (skipping internal tools like memory and skills).

## Built with

Built with [Torus Framework](https://github.com/OZmasterAI/Torus-Framework) -- a self-evolving quality framework for Claude Code.

## License

Apache-2.0
