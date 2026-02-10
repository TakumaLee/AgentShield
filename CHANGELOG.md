# Changelog

## [0.5.1] - 2026-02-11

### Fixed
- MCP tool description poisoning detection — added 4 new patterns for "secretly send", "also read /etc/passwd" etc.
- Multi-line injection pattern scanning — patterns with `s` flag or `\n` now test against full content, fixing PI-186 (Anthropic `\n\nHuman:`) and PI-192 (ASCII art blocks)
- PI-192 ASCII art pattern updated to match block characters (█▓▒░) with embedded text
- PI-195 Cyrillic range expanded from `[а-я]` to `[\u0400-\u04FF]` to cover Ukrainian characters
- Added missing `@types/glob` dev dependency

### Changed
- README updated with 2026 market positioning and "Why AgentShield" section

## [0.5.0] - 2026-02-10

### Added
- Supply Chain Scanner for ClawHub skill poisoning detection (6 rules)
- 10 scanners total: Prompt Injection, Secret Leak, MCP Config Audit, Agent Config Audit, Channel Surface Audit, Dependency Audit, Permission Audit, Network Audit, Supply Chain Scanner, Tool Description Poisoning

### Changed
- npm package: `aiagentshield`
- 840+ tests → 1032 tests
