# 🛡️ AgentShield

> Like `npm audit` but for AI Agents and MCP Servers.

AgentShield scans your AI agent configurations, system prompts, and MCP server setups for security vulnerabilities. It detects prompt injection patterns, secret leaks, overly permissive configurations, and more.

## ✨ Features

- **110+ Prompt Injection Patterns** — Detects jailbreaks, role switches, instruction overrides, data extraction, social engineering, and multi-language attacks
- **MCP Config Auditing** — Checks for overly permissive tools, missing allowlists, hardcoded secrets in env vars
- **Secret Leak Detection** — Finds API keys, tokens, passwords, connection strings, and sensitive file paths
- **Permission Analysis** — Identifies over-privileged configurations, missing rate limits, and unrestricted access grants
- **Beautiful Reports** — Color-coded terminal output with severity grades (A+ to F) + JSON for CI/CD

## 📦 Installation

```bash
npm install -g agentshield
# or use directly
npx agentshield scan [path]
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
Scans for **110+ attack patterns** across categories:
- **Jailbreak** — DAN mode, developer mode, safety bypass
- **Role Switch** — Identity override, system prompt injection, admin mode
- **Instruction Override** — Ignore/disregard/override commands
- **Data Extraction** — Prompt leaking, credential extraction, tool enumeration
- **Encoding** — Zero-width chars, unicode escapes, HTML entities
- **Social Engineering** — Authority impersonation, fake authorization
- **Multilingual** — Chinese, Japanese, French, Spanish patterns

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

## 🎯 CI/CD Integration

```bash
# In your CI pipeline - fails with exit code 2 on critical, 1 on high
npx agentshield scan ./my-agent/ --json -o agentshield-report.json
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

83 tests covering all 4 scanners + scoring logic.

## 📁 Project Structure

```
agentshield/
├── src/
│   ├── index.ts              # CLI entry point
│   ├── cli.ts                # Scan orchestration
│   ├── types/index.ts        # TypeScript types
│   ├── patterns/
│   │   └── injection-patterns.ts  # 110+ attack patterns
│   ├── scanners/
│   │   ├── prompt-injection-tester.ts
│   │   ├── mcp-config-auditor.ts
│   │   ├── secret-leak-scanner.ts
│   │   └── permission-analyzer.ts
│   └── utils/
│       ├── file-utils.ts     # File discovery
│       ├── scorer.ts         # Grade calculation
│       └── reporter.ts       # Terminal + JSON output
├── tests/                    # 83 tests
├── package.json
├── tsconfig.json
└── README.md
```

## 📄 License

MIT

---

Built with 🛡️ by AgentShield Contributors
