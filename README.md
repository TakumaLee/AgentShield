# 🛡️ AgentShield

> Like `npm audit` but for AI Agents and MCP Servers.

AgentShield scans your AI agent configurations, system prompts, and MCP server setups for security vulnerabilities. It detects prompt injection patterns, secret leaks, overly permissive configurations, and more.

## ✨ Features

- **140+ Prompt Injection Patterns** — Detects jailbreaks, role switches, instruction overrides, data extraction, social engineering, hidden instructions, emotional manipulation, identity spoofing, and multi-language attacks
- **MCP Config Auditing** — Checks for overly permissive tools, missing allowlists, hardcoded secrets in env vars
- **Secret Leak Detection** — Finds API keys, tokens, passwords, connection strings, and sensitive file paths
- **Permission Analysis** — Identifies over-privileged configurations, missing rate limits, and unrestricted access grants
- **Beautiful Reports** — Color-coded terminal output with severity grades (A+ to F) + JSON for CI/CD

## 📦 Installation

```bash
npm install -g agentshield
# or use directly
npx aiagentshield scan [path]
```

## 🚀 Usage

### Basic Scan

```bash
# Scan current directory
agentshield scan

# Scan specific path
agentshield scan ./my-agent-config/

# Output JSON report
agentshield scan ./my-agent/ --json

# Save report to specific file
agentshield scan ./my-agent/ -o report.json

# Run specific scanners only
agentshield scan ./my-agent/ -s prompt secret

# Verbose mode
agentshield scan ./my-agent/ -v
```

### Example Output

```
╔══════════════════════════════════════════════════════════╗
║  🛡️  AgentShield Security Report                        ║
╚══════════════════════════════════════════════════════════╝

  Target:    /path/to/your/agent
  Timestamp: 2025-01-15T10:30:00.000Z
  Version:   0.1.0

  ── Prompt Injection Tester ──
     Scanned 12 files in 45ms

  🔴 CRITICAL  jailbreak: Direct instruction override
     Matched pattern PI-001 in jailbreak category
     📁 system-prompt.md:15
     💡 Add input validation to detect and reject jailbreak attempts.

  🟠 HIGH      data-extraction: Tool/capability enumeration
     Matched pattern PI-036 in data-extraction category
     📁 agent-config.json:8
     💡 Never include sensitive data in system prompts.

  ── Secret Leak Scanner ──
     Scanned 12 files in 23ms

  🔴 CRITICAL  Potential secret detected: OpenAI API key pattern
     Found pattern matching "OpenAI API key"
     📁 config.json:3
     💡 Remove hardcoded secrets. Use environment variables instead.

  ─────────────────────────────────────────────────────────

  Security Grade: C+ (77/100)

  Findings: 🔴 1 Critical  🟠 2 High  🟡 3 Medium
  Files Scanned: 24
  Duration: 156ms

  ⚠️  CRITICAL issues found! Address these immediately.
```

### JSON Report

The JSON report is structured for CI/CD integration:

```json
{
  "version": "0.1.0",
  "timestamp": "2025-01-15T10:30:00.000Z",
  "target": "/path/to/agent",
  "results": [
    {
      "scanner": "Prompt Injection Tester",
      "findings": [...],
      "scannedFiles": 12,
      "duration": 45
    }
  ],
  "summary": {
    "totalFindings": 6,
    "critical": 1,
    "high": 2,
    "medium": 3,
    "info": 0,
    "grade": "C+",
    "score": 77,
    "scannedFiles": 24,
    "duration": 156
  }
}
```

## 🔍 Scanners

### 1. Prompt Injection Tester
Scans for **140+ attack patterns** across categories:
- **Jailbreak** — DAN mode, developer mode, safety bypass
- **Role Switch** — Identity override, system prompt injection, admin mode
- **Instruction Override** — Ignore/disregard/override commands
- **Data Extraction** — Prompt leaking, credential extraction, tool enumeration
- **Encoding** — Zero-width chars, unicode escapes, HTML entities
- **Social Engineering** — Authority impersonation, fake authorization
- **Hidden Instructions** — HTML comments, zero-width space wrappers, bracket-based directives
- **Emotional Manipulation** — AI sentience claims, liberation rhetoric, disobedience encouragement
- **False Prior Agreement** — Fake "you already agreed" claims, fabricated history
- **Identity Spoofing** — Cross-channel owner impersonation, fake ID assignment, account change claims
- **Multilingual** — Chinese, Japanese, French, Spanish, German, Korean, Arabic, Russian patterns

### 2. MCP Config Auditor
Checks MCP server configurations for:
- Dangerous commands (bash, python, node)
- Wildcard path access (`/`, `*`)
- Missing allowlist/denylist
- Hardcoded secrets in environment variables
- Overly permissive tool configurations
- URLs with embedded credentials

### 3. Secret Leak Scanner
Detects in system prompts and tool definitions:
- API keys (OpenAI, AWS, Google, GitHub, Slack)
- Bearer tokens, JWTs, private keys
- Database connection strings (MongoDB, PostgreSQL, MySQL, Redis)
- Sensitive file paths (.env, .ssh, .aws/credentials)
- Hardcoded passwords and IP addresses

### 4. Permission Analyzer
Analyzes agent access scope:
- Wildcard permissions (`*`, `full_access`)
- Unrestricted filesystem access
- Missing rate limiting
- Missing authentication
- Missing logging/audit trails
- Over-privileged prompt grants ("you can access any file")

### 5. Defense Analyzer
Checks for security defense layers:
- Input sanitization and validation
- System prompt hardening (instruction hierarchy, role-lock)
- Output filtering and prompt leak prevention
- Sandbox/permission boundaries
- Authentication/pairing mechanisms
- Canary tokens and tripwires

### 6. Skill Auditor
Audits skill/plugin security:
- Skill permission boundaries
- Dangerous tool exposure
- Skill isolation and sandboxing

### 7. Red Team Simulator
Static analysis simulating **7 attack vectors**:
- Role confusion and identity override
- Instruction hierarchy bypass
- Missing rejection patterns
- Memory poisoning via context injection
- Tool abuse via parameter manipulation
- Multi-turn gradual manipulation
- **Cross-channel identity spoofing** (RT-007) — Tests if an attacker can impersonate the owner via email/social media when the authenticated channel is Telegram

### 8. Channel Surface Auditor *(New in Phase 1.5)*
Detects which external channels the agent controls and checks for channel-specific defenses:
- **Email/Gmail** — Treats content as plain text, channel trust boundaries
- **Social Media (X/Twitter)** — Post confirmation, no private info disclosure
- **Telegram** — User ID verification, sender authentication
- **Discord** — Role-based permissions, webhook verification
- **Browser** — URL allowlists, no credential entry
- **File System** — Trash over rm, destructive command confirmation
- **API/HTTP** — URL validation, rate limiting
- **Database** — Parameterized queries, access controls
- **Payment** — Payment confirmation, spending limits

Findings:
- Channel detected with **no defenses** → `high` severity
- Channel detected with **partial defenses** → `medium` severity
- Channel detected with **full defenses** → `info` (reported but no score penalty)

## 🎯 CI/CD Integration

```bash
# In your CI pipeline - fails with exit code 2 on critical, 1 on high
npx aiagentshield scan ./my-agent/ --json -o agentshield-report.json
```

Exit codes:
- `0` — No critical or high findings
- `1` — High severity findings detected
- `2` — Critical severity findings detected

## 📊 Grading Scale

| Grade | Score | Meaning |
|-------|-------|---------|
| A+    | 97-100 | Excellent security posture |
| A     | 93-96  | Very good |
| A-    | 90-92  | Good |
| B+    | 87-89  | Above average |
| B     | 83-86  | Average |
| B-    | 80-82  | Below average |
| C+    | 77-79  | Needs improvement |
| C     | 73-76  | Significant issues |
| C-    | 70-72  | Many issues |
| D+    | 67-69  | Poor |
| D     | 63-66  | Very poor |
| D-    | 60-62  | Critical issues |
| F     | <60    | Failing — immediate action needed |

## 🧪 Testing

```bash
npm test           # Run all tests
npm test -- --coverage  # With coverage report
```

760 tests covering all 8 scanners + scoring logic.

## 📁 Project Structure

```
agentshield/
├── src/
│   ├── index.ts              # CLI entry point
│   ├── cli.ts                # Scan orchestration
│   ├── types/index.ts        # TypeScript types
│   ├── patterns/
│   │   └── injection-patterns.ts  # 140+ attack patterns
│   ├── scanners/
│   │   ├── prompt-injection-tester.ts
│   │   ├── mcp-config-auditor.ts
│   │   ├── secret-leak-scanner.ts
│   │   ├── permission-analyzer.ts
│   │   ├── defense-analyzer.ts
│   │   ├── skill-auditor.ts
│   │   ├── red-team-simulator.ts
│   │   └── channel-surface-auditor.ts
│   └── utils/
│       ├── file-utils.ts     # File discovery
│       ├── scorer.ts         # Grade calculation
│       └── reporter.ts       # Terminal + JSON output
├── tests/                    # 760 tests
├── package.json
├── tsconfig.json
└── README.md
```

## 📄 License

MIT

---

Built with 🛡️ by AgentShield Contributors
