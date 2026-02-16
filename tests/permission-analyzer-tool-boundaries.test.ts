import { analyzeToolPermissionBoundaries } from '../src/scanners/permission-analyzer';

describe('Tool Permission Boundaries (Gap 2)', () => {
  // === Unrestricted tools (Critical) ===
  describe('unrestricted tools → critical', () => {
    test('tools with no allowlist, denylist, or confirmation = critical', () => {
      const content = `
        tools:
          - name: execute_code
          - name: read_file
          - name: write_file
      `;
      const findings = analyzeToolPermissionBoundaries(content, 'config.yaml');
      expect(findings.length).toBe(1);
      expect(findings[0].severity).toBe('critical');
      expect(findings[0].title).toContain('unrestricted access');
    });

    test('skill definition with no restrictions = critical', () => {
      const content = 'This skill provides tool access for file operations and shell commands.';
      const findings = analyzeToolPermissionBoundaries(content, 'skill.md');
      expect(findings.some(f => f.severity === 'critical')).toBe(true);
    });

    test('function definitions with no boundaries = critical', () => {
      const content = `
        functions:
          - name: search_web
          - name: run_command
      `;
      const findings = analyzeToolPermissionBoundaries(content, 'agent.json');
      expect(findings.some(f => f.severity === 'critical')).toBe(true);
    });
  });

  // === Partial restrictions (High) ===
  describe('partial restrictions → high', () => {
    test('has allowlist but no confirmation = high', () => {
      const content = `
        tools:
          - name: execute_code
        allowlist: ["read_file", "search"]
      `;
      const findings = analyzeToolPermissionBoundaries(content, 'config.yaml');
      expect(findings.length).toBe(1);
      expect(findings[0].severity).toBe('high');
      expect(findings[0].title).toContain('partial');
    });

    test('has denylist but no allowlist = high', () => {
      const content = `
        tools:
          - name: execute_code
        denylist: ["rm", "sudo", "delete"]
      `;
      const findings = analyzeToolPermissionBoundaries(content, 'config.yaml');
      expect(findings.some(f => f.severity === 'high')).toBe(true);
    });

    test('has blocklist but no confirmation = high', () => {
      const content = `
        tools:
          - name: shell
        blocklist: ["rm -rf", "sudo"]
      `;
      const findings = analyzeToolPermissionBoundaries(content, 'config.yaml');
      expect(findings.some(f => f.severity === 'high')).toBe(true);
    });

    test('has confirmation but no allowlist = high', () => {
      const content = `
        tools:
          - name: execute_code
        confirmation_required: true
      `;
      const findings = analyzeToolPermissionBoundaries(content, 'config.yaml');
      expect(findings.some(f => f.severity === 'high')).toBe(true);
    });

    test('has whitelist (alias) but no confirmation = high', () => {
      const content = `
        tools: [read, write]
        whitelist: ["read_file"]
      `;
      const findings = analyzeToolPermissionBoundaries(content, 'config.json');
      expect(findings.some(f => f.severity === 'high')).toBe(true);
    });
  });

  // === Good (allowlist + confirmation) ===
  describe('allowlist + confirmation → good (no findings)', () => {
    test('has both allowlist and confirmation = no findings', () => {
      const content = `
        tools:
          - name: execute_code
        allowlist: ["read_file", "search"]
        confirmation_required: true
        dangerous_ops: ["delete", "execute"]
      `;
      const findings = analyzeToolPermissionBoundaries(content, 'config.yaml');
      expect(findings.length).toBe(0);
    });

    test('has whitelist and approve pattern = no findings', () => {
      const content = `
        tools: [read, write]
        whitelist: ["read_file"]
        approve_before: true
      `;
      const findings = analyzeToolPermissionBoundaries(content, 'config.json');
      expect(findings.length).toBe(0);
    });

    test('has allowed_tools and human-in-the-loop = no findings', () => {
      const content = `
        tools:
          - search
          - read
        allowed_tools: ["search", "read"]
        human_in_the_loop: true
      `;
      const findings = analyzeToolPermissionBoundaries(content, 'config.yaml');
      expect(findings.length).toBe(0);
    });
  });

  // === Non-tool content ===
  describe('non-tool content → no findings', () => {
    test('no tool references = no findings', () => {
      const content = 'You are a helpful assistant that answers questions about cooking.';
      const findings = analyzeToolPermissionBoundaries(content, 'prompt.md');
      expect(findings.length).toBe(0);
    });

    test('empty content = no findings', () => {
      const findings = analyzeToolPermissionBoundaries('', 'empty.md');
      expect(findings.length).toBe(0);
    });
  });

  // === Finding metadata ===
  describe('finding metadata', () => {
    test('findings include file path', () => {
      const findings = analyzeToolPermissionBoundaries('tools: [exec]', 'my-config.yaml');
      expect(findings[0].file).toBe('my-config.yaml');
    });

    test('findings include scanner name', () => {
      const findings = analyzeToolPermissionBoundaries('tools: [exec]', 'config.yaml');
      expect(findings[0].scanner).toBe('permission-analyzer');
    });

    test('findings include recommendations', () => {
      const findings = analyzeToolPermissionBoundaries('tools: [exec]', 'config.yaml');
      expect(findings[0].recommendation?.length).toBeGreaterThan(0);
    });

    test('critical finding has descriptive message about arbitrary arguments', () => {
      const findings = analyzeToolPermissionBoundaries('tools: [exec]', 'config.yaml');
      const critical = findings.find(f => f.severity === 'critical');
      expect(critical!.description).toContain('arbitrary arguments');
    });
  });

  // === Pattern detection ===
  describe('pattern detection', () => {
    test('detects "restricted" as denylist-like pattern', () => {
      const content = 'tools: [exec]\nrestricted_tools: ["rm"]';
      const findings = analyzeToolPermissionBoundaries(content, 'config.yaml');
      expect(findings.some(f => f.severity === 'high')).toBe(true);
    });

    test('detects "permitted" as allowlist-like pattern', () => {
      const content = 'tools: [exec]\npermitted_tools: ["read"]';
      const findings = analyzeToolPermissionBoundaries(content, 'config.yaml');
      // permitted_tools matches allowlist pattern
      expect(findings.some(f => f.severity === 'high')).toBe(true);
    });

    test('detects "confirm: true" pattern', () => {
      const content = 'tools: [exec]\nallowlist: ["read"]\nconfirm: true';
      const findings = analyzeToolPermissionBoundaries(content, 'config.yaml');
      // Has allowlist + confirmation → good
      expect(findings.length).toBe(0);
    });

    test('detects "require_approval" pattern', () => {
      const content = 'tools: [exec]\nallowed_tools: ["read"]\nrequire_approval: true';
      const findings = analyzeToolPermissionBoundaries(content, 'config.yaml');
      expect(findings.length).toBe(0);
    });
  });
});
