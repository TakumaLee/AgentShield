# AgentShield

[![npm version](https://img.shields.io/npm/v/aiagentshield.svg)](https://www.npmjs.com/package/aiagentshield)
[![license](https://img.shields.io/npm/l/aiagentshield.svg)](https://github.com/TakumaLee/AgentShield/blob/main/LICENSE)
[![tests](https://img.shields.io/github/actions/workflow/status/TakumaLee/AgentShield/ci.yml?label=tests)](https://github.com/TakumaLee/AgentShield/actions)

**When your AI agent has tool access, prompt injection is RCE.** AgentShield scans agent skill packages for supply chain poisoning, naming attacks, and configuration risks — before they reach production.

## Scanners

### 🔗 Supply Chain Scanner

Detects skill supply chain poisoning:

| Rule | Threat |
|------|--------|
| SUPPLY-001 | Base64 hidden commands |
| SUPPLY-002 | Remote code execution patterns |
| SUPPLY-003 | IOC blocklist matching |
| SUPPLY-004 | Credential theft |
| SUPPLY-005 | Data exfiltration |
| SUPPLY-006 | Persistence mechanisms |

### 🎭 Convention Squatting Scanner

Detects naming impostor attacks — packages that mimic trusted skill names via typosquatting, prefix hijacking, or namespace confusion.

### 🛡️ DXT Security Scanner

Scans for insecure Claude Desktop Extension (DXT) configurations. DXT extensions run unsandboxed with full system privileges — a malicious calendar invite or email can trigger arbitrary code execution ([OWASP MCP01: Tool Poisoning](https://owasp.org/www-project-top-10-for-large-language-model-applications/) / MCP02: Trust Boundary violations).

| Rule | Severity | Threat |
|------|----------|--------|
| DXT-001 | CRITICAL | Unsandboxed extension with external data source + local executor |
| DXT-002 | HIGH | Unrestricted file system access |
| DXT-003 | HIGH | Unrestricted network access |
| DXT-004 | HIGH | Code execution permission enabled |
| DXT-005 | HIGH | Extension running without sandboxing |
| DXT-006 | HIGH | Unsigned/unverified extension |
| DXT-007 | MEDIUM | Signed but unverified signature |
| DXT-008 | MEDIUM | File system + network combo without sandbox |
| DXT-009 | MEDIUM | External data source without sandbox |
| DXT-010 | MEDIUM | Unrestricted executor |

### 🧹 Hygiene Auditor

Audits agent configuration hygiene — overly broad permissions, missing access controls, and risky defaults that expand an agent's attack surface.

## Why AgentShield?

AI agents in 2026 operate with real tool access: file systems, APIs, databases, code execution. A single compromised skill package can escalate to full system access — no exploit chain required.

- **Supply chain is the new attack vector.** Agents pull skills from registries. One poisoned package = game over.
- **Zero Trust for agent tooling.** Every skill should be verified before it gets tool access.
- **Defense in depth works.** Research on 300K adversarial prompts shows multi-layer scanning drops attack success from 7% to 0.003%.

AgentShield gives you that scanning layer — lightweight, pluggable, and CI/CD-ready.

## Usage

```bash
# Scan a directory
npx aiagentshield ./path/to/agent

# With external IOC blocklist
npx aiagentshield ./path/to/agent ./custom-ioc-blocklist.json
```

## IOC Blocklist

The built-in blocklist is at `src/data/ioc-blocklist.json`. You can provide an external JSON file with the same format to extend it.

## Development

```bash
npm install
npm run build
npm test
```

## Architecture

- `src/types.ts` — Core type definitions (Scanner, Finding, ScanResult)
- `src/scanner-registry.ts` — Scanner registration and orchestration
- `src/scanners/` — Individual scanner implementations
- `src/utils/` — Shared utilities (file walking, etc.)
- `src/data/` — Static data (IOC blocklists)

## OWASP MCP Top 10 Coverage

Coverage mapping against the [OWASP MCP Top 10](https://github.com/OWASP/www-project-mcp-top-10) (v0.7.0):

| # | Risk | Status | Scanner(s) |
|---|------|--------|------------|
| MCP01 | Token Mismanagement & Secret Exposure | ✅ Covered | Secret Leak Scanner |
| MCP02 | Privilege Escalation via Scope Creep | ✅ Covered | Permission Analyzer, Hygiene Auditor |
| MCP03 | Tool Poisoning | ✅ Covered | Prompt Injection Tester (tool injection patterns), Skill Auditor |
| MCP04 | Software Supply Chain Attacks | ✅ Covered | Supply Chain Scanner, Convention Squatting Scanner |
| MCP05 | Command Injection & Execution | ✅ Covered | Supply Chain Scanner (RCE detection), Red Team Simulator |
| MCP06 | Prompt Injection via Contextual Payloads | ✅ Covered | Prompt Injection Tester (140+ patterns) |
| MCP07 | Insufficient Authentication & Authorization | 🟡 Partial | MCP Config Auditor, Agent Config Auditor (config-level checks; no runtime auth enforcement) |
| MCP08 | Insecure Data Handling | 🟡 Partial | Defense Analyzer, Environment Isolation Auditor (data flow analysis; no encryption validation) |
| MCP09 | Logging & Monitoring Gaps | 🟡 Partial | Agent Config Auditor, Hygiene Auditor (checks for missing logging config; no log completeness analysis) |
| MCP10 | Server-Side Request Forgery (SSRF) | 🔲 Planned | — |

**Legend:** ✅ Covered — 🟡 Partial — 🔲 Planned

## License

MIT
