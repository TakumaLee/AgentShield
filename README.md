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

## License

MIT
