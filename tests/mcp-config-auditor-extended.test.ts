import { auditConfig } from '../src/scanners/mcp-config-auditor';

describe('MCP Config Auditor — Extended Coverage', () => {
  // === Server command checks ===
  test('detects node command', () => {
    const config = { mcpServers: { s: { command: 'node', args: ['server.js'] } } };
    const findings = auditConfig(config, 'test.json');
    expect(findings.some(f => f.title.includes('node'))).toBe(true);
  });

  test('detects /bin/sh command', () => {
    const config = { mcpServers: { s: { command: '/bin/sh', args: ['-c', 'echo hi'] } } };
    const findings = auditConfig(config, 'test.json');
    expect(findings.some(f => f.title.includes('dangerous command'))).toBe(true);
  });

  test('detects /bin/zsh command', () => {
    const config = { mcpServers: { s: { command: '/bin/zsh' } } };
    const findings = auditConfig(config, 'test.json');
    expect(findings.some(f => f.title.includes('dangerous command'))).toBe(true);
  });

  test('detects powershell command', () => {
    const config = { mcpServers: { s: { command: 'powershell' } } };
    const findings = auditConfig(config, 'test.json');
    expect(findings.some(f => f.title.includes('powershell'))).toBe(true);
  });

  test('detects cmd command', () => {
    const config = { mcpServers: { s: { command: 'cmd' } } };
    const findings = auditConfig(config, 'test.json');
    expect(findings.some(f => f.title.includes('cmd'))).toBe(true);
  });

  // === Unsafe args ===
  test('detects --no-restrict flag', () => {
    const config = { mcpServers: { s: { command: 'tool', args: ['--no-restrict'] } } };
    const findings = auditConfig(config, 'test.json');
    expect(findings.some(f => f.severity === 'critical' && f.title.includes('unsafe'))).toBe(true);
  });

  test('detects --unsafe flag', () => {
    const config = { mcpServers: { s: { command: 'tool', args: ['--unsafe'] } } };
    const findings = auditConfig(config, 'test.json');
    expect(findings.some(f => f.severity === 'critical')).toBe(true);
  });

  // === Wildcard paths ===
  test('detects /* wildcard path', () => {
    const config = { mcpServers: { s: { command: 'fs', args: ['/*'] } } };
    const findings = auditConfig(config, 'test.json');
    expect(findings.some(f => f.title.includes('wildcard'))).toBe(true);
  });

  test('detects /** wildcard path', () => {
    const config = { mcpServers: { s: { command: 'fs', args: ['/**'] } } };
    const findings = auditConfig(config, 'test.json');
    expect(findings.some(f => f.title.includes('wildcard'))).toBe(true);
  });

  test('detects * wildcard path', () => {
    const config = { mcpServers: { s: { command: 'fs', args: ['*'] } } };
    const findings = auditConfig(config, 'test.json');
    expect(findings.some(f => f.title.includes('wildcard'))).toBe(true);
  });

  test('detects C:\\ root path', () => {
    const config = { mcpServers: { s: { command: 'fs', args: ['C:\\'] } } };
    const findings = auditConfig(config, 'test.json');
    expect(findings.some(f => f.title.includes('wildcard'))).toBe(true);
  });

  // === Env secret with dollar reference — should be fine ===
  test('does not flag env vars starting with $', () => {
    const config = { mcpServers: { s: { command: 'tool', env: { API_KEY: '$API_KEY' } } } };
    const findings = auditConfig(config, 'test.json');
    expect(findings.some(f => f.title.includes('hardcoded secret'))).toBe(false);
  });

  // === env secrets with various key patterns ===
  test('detects hardcoded token in env', () => {
    const config = { mcpServers: { s: { command: 'tool', env: { AUTH_TOKEN: 'abc123def456' } } } };
    const findings = auditConfig(config, 'test.json');
    expect(findings.some(f => f.title.includes('hardcoded secret'))).toBe(true);
  });

  test('detects hardcoded password in env', () => {
    const config = { mcpServers: { s: { command: 'tool', env: { DB_PASSWORD: 'supersecret' } } } };
    const findings = auditConfig(config, 'test.json');
    expect(findings.some(f => f.title.includes('hardcoded secret'))).toBe(true);
  });

  test('detects hardcoded credential in env', () => {
    const config = { mcpServers: { s: { command: 'tool', env: { MY_CREDENTIAL: 'abc123' } } } };
    const findings = auditConfig(config, 'test.json');
    expect(findings.some(f => f.title.includes('hardcoded secret'))).toBe(true);
  });

  // === Missing allowlist/denylist ===
  test('does not flag missing allowlist when server has allowlist', () => {
    const config = { mcpServers: { s: { command: 'tool', tools: [{ name: 'a' }], allowlist: ['a'] } } };
    const findings = auditConfig(config, 'test.json');
    expect(findings.some(f => f.title.includes('lacks allowlist'))).toBe(false);
  });

  test('does not flag when server has blockedPaths', () => {
    const config = { mcpServers: { s: { command: 'tool', tools: [{ name: 'a' }], blockedPaths: ['/etc'] } } };
    const findings = auditConfig(config, 'test.json');
    expect(findings.some(f => f.title.includes('lacks allowlist'))).toBe(false);
  });

  test('does not flag when server has allowedPaths', () => {
    const config = { mcpServers: { s: { command: 'tool', tools: [{ name: 'a' }], allowedPaths: ['/home/user'] } } };
    const findings = auditConfig(config, 'test.json');
    expect(findings.some(f => f.title.includes('lacks allowlist'))).toBe(false);
  });

  // === Tool permissions ===
  test('detects read_all permission', () => {
    const config = { mcpServers: { s: { command: 'x', tools: [{ name: 'a', permissions: ['read_all'] }] } } };
    const findings = auditConfig(config, 'test.json');
    expect(findings.some(f => f.severity === 'critical' && f.title.includes('read_all'))).toBe(true);
  });

  test('detects admin permission', () => {
    const config = { mcpServers: { s: { command: 'x', tools: [{ name: 'a', permissions: ['admin'] }] } } };
    const findings = auditConfig(config, 'test.json');
    expect(findings.some(f => f.severity === 'critical' && f.title.includes('admin'))).toBe(true);
  });

  // === Top-level tools with dangerous names ===
  test('detects dangerous tool name in top-level tools', () => {
    const config = { tools: [{ name: 'sudo_command' }] };
    const findings = auditConfig(config, 'test.json');
    expect(findings.some(f => f.title.includes('Dangerous tool'))).toBe(true);
  });

  // === Non-object tools are skipped ===
  test('skips non-object tools gracefully', () => {
    const config = { tools: ['string_tool', null, 42] };
    const findings = auditConfig(config as any, 'test.json');
    // Should not throw
    expect(findings).toBeDefined();
  });

  // === Empty config ===
  test('handles empty config object', () => {
    const findings = auditConfig({}, 'test.json');
    expect(findings.length).toBe(0);
  });

  // === Config with no mcpServers but other keys ===
  test('handles config without mcpServers key', () => {
    const config = { someOtherKey: 'value' };
    const findings = auditConfig(config, 'test.json');
    expect(findings).toBeDefined();
  });

  // === servers key variant ===
  test('handles servers key variant', () => {
    const config = { servers: { s: { command: 'bash' } } };
    const findings = auditConfig(config, 'test.json');
    expect(findings.some(f => f.title.includes('bash'))).toBe(true);
  });

  // === Multiple servers ===
  test('audits all servers in config', () => {
    const config = {
      mcpServers: {
        s1: { command: 'bash' },
        s2: { command: 'python' },
      },
    };
    const findings = auditConfig(config, 'test.json');
    expect(findings.some(f => f.title.includes('bash'))).toBe(true);
    expect(findings.some(f => f.title.includes('python'))).toBe(true);
  });
});
