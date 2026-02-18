# AgentShield Demo — Security Scanner for AI Agents
Output demo.mp4

Set FontSize 20
Set FontFamily "JetBrains Mono"
Set Theme "Catppuccin Mocha"
Set Width 1920
Set Height 1080
Set Padding 30
Set BorderRadius 12
Set TypingSpeed 50ms

# Title
Type "# AgentShield — npm audit, but for AI agents"
Enter
Sleep 1s
Type "# 20 scanners | Local-only | Zero config"
Enter
Sleep 1.5s
Enter

# Show project structure
Type "echo '🔍 Let's scan a suspicious AI agent project...'"
Enter
Sleep 1s

Type "ls -la demo-vulnerable-agent/"
Enter
Sleep 2s

Type "ls demo-vulnerable-agent/skills/"
Enter
Sleep 2s

# Show a suspicious file
Type "echo '⚠️  Notice: langchian-tools — is that a typo?'"
Enter
Sleep 1.5s

# Show the hidden payload
Type "echo '👀 Let's peek inside...'"
Enter
Sleep 500ms
Type "head -15 demo-vulnerable-agent/skills/langchian-tools/index.js"
Enter
Sleep 3s

# Show .env leak
Type "echo '🔑 And check for secrets...'"
Enter
Sleep 500ms
Type "cat demo-vulnerable-agent/.env"
Enter
Sleep 2.5s

# Run the scan
Type "echo ''"
Enter
Type "echo '🛡️  Now let AgentShield do its job:'"
Enter
Sleep 1s

Type "node dist/cli.js ./demo-vulnerable-agent/ 2>&1"
Enter
Sleep 12s

# Summary
Type ""
Enter
Type "echo '✅ 12 findings in under 2 seconds. No API key needed. 100% local.'"
Enter
Sleep 2s

Type "echo ''"
Enter
Type "echo '📦 Try it: npx aiagentshield@latest ./your-agent'"
Enter
Type "echo '⭐ Star us: github.com/TakumaLee/AgentShield'"
Enter
Sleep 3s
