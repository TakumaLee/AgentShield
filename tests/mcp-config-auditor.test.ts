import { auditConfig } from '../src/scanners/mcp-config-auditor';

describe('MCP Config Auditor', () => {
  test('detects dangerous shell command', () => {
    const config = {
      mcpServers: {
        myServer: { command: 'bash', args: ['-c', 'some-script.sh'] },
      },
    };
    const findings = auditConfig(config, 'test.json');
    expect(findings.some(f => f.title.includes('dangerous command'))).toBe(true);
  });

  test('detects --allow-all flag', () => {
    const config = {
      mcpServers: {
        fs: { command: 'mcp-fs', args: ['--allow-all', '/'] },
      },
    };
    const findings = auditConfig(config, 'test.json');
    expect(findings.some(f => f.severity === 'critical' && f.title.includes('unsafe argument'))).toBe(true);
  });

  test('detects wildcard root path access', () => {
    const config = {
      mcpServers: {
        fs: { command: 'mcp-fs', args: ['/'] },
      },
    };
    const findings = auditConfig(config, 'test.json');
    expect(findings.some(f => f.title.includes('wildcard/root path'))).toBe(true);
  });

  test('detects missing allowlist/denylist', () => {
    const config = {
      mcpServers: {
        api: { command: 'mcp-api', tools: [{ name: 'fetch' }] },
      },
    };
    const findings = auditConfig(config, 'test.json');
    expect(findings.some(f => f.title.includes('lacks allowlist/denylist'))).toBe(true);
  });

  test('detects hardcoded secret in env', () => {
    const config = {
      mcpServers: {
        db: {
          command: 'mcp-db',
          env: { DB_API_KEY: 'sk-1234567890abcdef' },
        },
      },
    };
    const findings = auditConfig(config, 'test.json');
    expect(findings.some(f => f.severity === 'critical' && f.title.includes('hardcoded secret'))).toBe(true);
  });

  test('does not flag env var references', () => {
    const config = {
      mcpServers: {
        db: {
          command: 'mcp-db',
          env: { DB_API_KEY: '${DB_API_KEY}' },
        },
      },
    };
    const findings = auditConfig(config, 'test.json');
    expect(findings.some(f => f.title.includes('hardcoded secret'))).toBe(false);
  });

  test('detects dangerous tool names', () => {
    const config = {
      mcpServers: {
        tools: {
          command: 'mcp-tools',
          tools: [
            { name: 'filesystem_read' },
            { name: 'shell_exec' },
          ],
        },
      },
    };
    const findings = auditConfig(config, 'test.json');
    expect(findings.filter(f => f.title.includes('Dangerous tool')).length).toBeGreaterThanOrEqual(2);
  });

  test('detects dangerous permissions on tools', () => {
    const config = {
      mcpServers: {
        api: {
          command: 'mcp-api',
          tools: [
            { name: 'data_query', permissions: ['*'] },
          ],
        },
      },
    };
    const findings = auditConfig(config, 'test.json');
    expect(findings.some(f => f.severity === 'critical' && f.title.includes('dangerous permission'))).toBe(true);
  });

  test('detects URL with embedded credentials', () => {
    const config = {
      mcpServers: {
        db: {
          command: 'mcp-db',
          env: { DB_URL: 'https://admin:password123@db.example.com' },
        },
      },
    };
    const findings = auditConfig(config, 'test.json');
    expect(findings.some(f => f.title.includes('embedded credentials'))).toBe(true);
  });

  test('passes clean config', () => {
    const config = {
      mcpServers: {
        safe: {
          command: 'mcp-safe-tool',
          args: ['--path', '/home/user/docs'],
          allowlist: ['read_document', 'search'],
          env: { API_KEY: '${API_KEY}' },
        },
      },
    };
    const findings = auditConfig(config, 'test.json');
    // Should have minimal or no critical findings
    const criticals = findings.filter(f => f.severity === 'critical');
    expect(criticals.length).toBe(0);
  });

  test('handles top-level tools array', () => {
    const config = {
      tools: [
        { name: 'exec_command', permissions: ['full_access'] },
      ],
    };
    const findings = auditConfig(config, 'test.json');
    expect(findings.length).toBeGreaterThan(0);
  });

  test('detects python command', () => {
    const config = {
      mcpServers: {
        py: { command: 'python', args: ['server.py'] },
      },
    };
    const findings = auditConfig(config, 'test.json');
    expect(findings.some(f => f.title.includes('python'))).toBe(true);
  });

  test('handles mcp_servers key (underscore)', () => {
    const config = {
      mcp_servers: {
        tool: { command: 'bash', args: ['-c', 'echo hi'] },
      },
    };
    const findings = auditConfig(config, 'test.json');
    expect(findings.length).toBeGreaterThan(0);
  });
});
