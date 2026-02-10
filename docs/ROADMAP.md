
## Convention File Squatting Detection (New — 2026-02-10)
**Source**: Community risk disclosure — .md convention filenames registered as domains
**Attack**: Agent frameworks that resolve filenames via URL (instead of local fs read) could fetch attacker-controlled content from domains like `heartbeat.md`, `readme.md`, `agents.md`, `soul.md`
**Impact**: Periodic prompt injection via heartbeat, config poisoning, identity override
**Detection rules to add**:
- Scan agent config for any file read that could resolve to a URL
- Flag convention filenames that match known registered TLDs (.md = Moldova TLD)
- Check if agent framework distinguishes local fs read vs HTTP fetch
- Warn if heartbeat/config files are fetched over network instead of local read
**Priority**: High — affects all agent frameworks with convention files
