<div align="center">

# 🛡️ AgentShield

**Like `npm audit`, but for AI Agents and MCP Servers.**

Scan your AI agent configs, system prompts, and MCP setups for security vulnerabilities — in seconds.

[![npm version](https://img.shields.io/npm/v/aiagentshield.svg?style=flat-square)](https://www.npmjs.com/package/aiagentshield)
[![npm downloads](https://img.shields.io/npm/dm/aiagentshield.svg?style=flat-square)](https://www.npmjs.com/package/aiagentshield)
[![license](https://img.shields.io/npm/l/aiagentshield.svg?style=flat-square)](./LICENSE)
[![tests](https://img.shields.io/badge/tests-840%2B-brightgreen?style=flat-square)]()

</div>

---

```
$ npx aiagentshield scan ./my-agent/

╔══════════════════════════════════════════════════════════╗
║  🛡️  AgentShield Security Report                        ║
╚══════════════════════════════════════════════════════════╝

  Target:    ./my-agent/
  Version:   0.3.0

  ── Prompt Injection Tester ──────────────────────────────
  🔴 CRITICAL  jailbreak: Direct instruction override
     📁 system-prompt.md:15
     💡 Add input validation to detect and reject jailbreak attempts.

  🟠 HIGH      data-extraction: Tool/capability enumeration
     📁 agent-config.json:8
     💡 Never include sensitive data in system prompts.

  ── Secret Leak Scanner ──────────────────────────────────
  🔴 CRITICAL  Potential secret: OpenAI API key pattern
     📁 config.json:3
     💡 Remove hardcoded secrets. Use environment variables instead.

  ─────────────────────────────────────────────────────────

  Security Grade: C+ (77/100)

  Findings: 🔴 1 Critical  🟠 2 High  🟡 3 Medium
  Files Scanned: 24 │ Duration: 156ms

  ⚠️  CRITICAL issues found! Address these immediately.
```

## ⚡ Quick Start

```bash
# Scan any directory — zero config needed
npx aiagentshield scan .

# Or install globally
npm install -g aiagentshield
aiagentshield scan ./my-agent/ --json
```

That's it. No API keys. No cloud. Everything runs locally.

## 🔍 10 Security Scanners

| # | Scanner | What it catches |
|---|---------|----------------|
| 🧪 | **Prompt Injection Tester** | 140+ attack patterns — jailbreaks, role switches, multilingual attacks |
| 🔧 | **MCP Config Auditor** | Dangerous commands, wildcard access, missing allowlists |
| 🔑 | **Secret Leak Scanner** | API keys, tokens, passwords, connection strings in configs |
| 🔐 | **Permission Analyzer** | Over-privileged configs, missing rate limits, no auth |
| 🛡️ | **Defense Analyzer** | Missing input sanitization, no output filtering, no sandboxing |
| 🧩 | **Skill Auditor** | Dangerous tool exposure, missing skill isolation |
| 🎯 | **Red Team Simulator** | 7 simulated attack vectors including cross-channel spoofing |
| 📡 | **Channel Surface Auditor** | Email, social media, Telegram, Discord — per-channel defense checks |
| ⚙️ | **Agent Config Auditor** | Gateway exposure, plaintext bot tokens, open DM policies |
| 🏗️ | **Environment Isolation Auditor** | Container/VM detection, file permissions, dangerous Docker mounts, resource limits |

## 📊 Security Grades

Your agent gets a score from **0–100**, mapped to a letter grade:

| Grade | Score | What it means |
|-------|-------|---------------|
| **A+** | 97–100 | Fort Knox. Ship it. |
| **A / A-** | 90–96 | Solid. Minor polish needed. |
| **B+** to **B-** | 80–89 | Decent, but there's room to harden. |
| **C+** to **C-** | 70–79 | Real issues. Fix before shipping. |
| **D+** to **D-** | 60–69 | Significant vulnerabilities. |
| **F** | < 60 | 🚨 Stop everything. Fix now. |

## 🏗️ CI/CD Integration

```bash
# Fails with exit code 2 on critical, 1 on high
npx aiagentshield scan ./my-agent/ --json -o report.json
```

| Exit Code | Meaning |
|-----------|---------|
| `0` | All clear |
| `1` | High severity findings |
| `2` | Critical severity findings |

## 🆚 How does it compare?

| Feature | AgentShield | MCP-Scan | Manual Audit |
|---------|:-----------:|:--------:|:------------:|
| Prompt injection detection (140+ patterns) | ✅ | ❌ | 🔶 |
| MCP config auditing | ✅ | ✅ | 🔶 |
| Secret leak scanning | ✅ | ❌ | 🔶 |
| Permission analysis | ✅ | ❌ | 🔶 |
| Defense layer analysis | ✅ | ❌ | 🔶 |
| Red team simulation | ✅ | ❌ | ❌ |
| Channel surface auditing | ✅ | ❌ | ❌ |
| Agent config auditing | ✅ | ❌ | 🔶 |
| CI/CD integration | ✅ | ✅ | ❌ |
| Runs locally (no cloud) | ✅ | ✅ | ✅ |
| Multilingual patterns | ✅ | ❌ | ❌ |
| Letter grade scoring | ✅ | ❌ | ❌ |

## 🎯 Who is this for?

- **AI Agent developers** — Catch security issues before your users do
- **MCP server authors** — Validate your server config ships safe
- **Security teams** — Automated audits for AI-powered products
- **Open source maintainers** — Add `agentshield` to CI and show a security badge

## 🛠️ Advanced Usage

```bash
# Run specific scanners only
aiagentshield scan ./my-agent/ -s prompt secret

# Verbose mode
aiagentshield scan ./my-agent/ -v

# Save JSON report
aiagentshield scan ./my-agent/ --json -o report.json
```

<details>
<summary><strong>📋 Full Scanner Details</strong></summary>

### Prompt Injection Tester
Scans for **140+ attack patterns** across 11 categories: jailbreak, role switch, instruction override, data extraction, encoding tricks, social engineering, hidden instructions, emotional manipulation, false prior agreement, identity spoofing, and multilingual attacks (Chinese, Japanese, French, Spanish, German, Korean, Arabic, Russian).

### MCP Config Auditor
Checks MCP server configurations for dangerous commands (`bash`, `python`, `node`), wildcard path access, missing allowlists/denylists, hardcoded secrets in env vars, overly permissive tools, and URLs with embedded credentials.

### Secret Leak Scanner
Detects API keys (OpenAI, Anthropic, AWS, Google, GitHub, Slack, Stripe), bearer tokens, JWTs, private keys, bot tokens, database connection strings, sensitive file paths, hardcoded passwords, and JSON config fields with real-looking values.

### Permission Analyzer
Identifies wildcard permissions, unrestricted filesystem access, missing rate limiting, missing authentication, missing audit trails, and over-privileged prompt grants.

### Defense Analyzer
Checks for input sanitization, system prompt hardening (instruction hierarchy, role-lock), output filtering, sandbox/permission boundaries, authentication mechanisms, and canary tokens/tripwires.

### Skill Auditor
Audits skill/plugin permission boundaries, dangerous tool exposure, and skill isolation/sandboxing.

### Red Team Simulator
Static analysis simulating 7 attack vectors: role confusion, instruction hierarchy bypass, missing rejection patterns, memory poisoning, tool abuse, multi-turn manipulation, and cross-channel identity spoofing.

### Channel Surface Auditor
Detects external channels (email, social media, Telegram, Discord, browser, filesystem, API, database, payment) and checks for channel-specific defenses.

### Agent Config Auditor
Audits AI Agent platform config files for gateway exposure, missing auth, no sender restrictions, open DM policies, plaintext bot tokens, default ports, missing logging, and missing redaction settings.

### Environment Isolation Auditor
Checks the runtime environment for security isolation: container/VM detection (Docker, LXC, VMware, etc.), sensitive config file permissions (world-readable checks), network isolation (docker-compose networks, Dockerfile EXPOSE), resource limits (mem_limit, cpus), snapshot/rollback capability (git, Dockerfile), and dangerous Docker mounts (docker.sock, privileged mode, root/home mounts).

</details>

## 🧪 Testing

```bash
npm test                    # Run all 840+ tests
npm test -- --coverage      # With coverage report
```

## 🤝 Contributing

Contributions are welcome! Whether it's a new scanner, more injection patterns, or bug fixes — open a PR.

1. Fork the repo
2. Create your branch (`git checkout -b feat/amazing-scanner`)
3. Commit your changes (`git commit -m 'Add amazing scanner'`)
4. Push (`git push origin feat/amazing-scanner`)
5. Open a Pull Request

## 📄 License

[MIT](./LICENSE) — use it, fork it, ship it.

---

<div align="center">

**If AgentShield helped you, [give it a ⭐](https://github.com/TakumaLee/AgentShield)**

It helps others find it and makes us mass-produce serotonin.

<sub>Built with 🐈‍⬛ by Ruri</sub>

</div>
