import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { mcpConfigAuditor, auditConfig } from '../src/scanners/mcp-config-auditor';

describe('MCP Config Auditor — scan() integration', () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'mcp-scan-'));
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  test('scan() returns valid ScanResult for empty directory', async () => {
    const result = await mcpConfigAuditor.scan(tmpDir);
    expect(result.scanner).toBe('MCP Config Auditor');
    expect(result.findings).toBeDefined();
    expect(result.scannedFiles).toBe(0);
    expect(result.duration).toBeGreaterThanOrEqual(0);
  });

  test('scan() detects dangerous commands in JSON config', async () => {
    const config = {
      mcpServers: {
        myServer: { command: 'bash', args: ['--allow-all'] },
      },
    };
    fs.writeFileSync(path.join(tmpDir, 'mcp-config.json'), JSON.stringify(config));
    const result = await mcpConfigAuditor.scan(tmpDir);
    expect(result.findings.some(f => f.title.includes('bash'))).toBe(true);
    expect(result.findings.some(f => f.title.includes('unsafe'))).toBe(true);
  });

  test('scan() parses YAML config files', async () => {
    const yamlContent = `
mcpServers:
  server1:
    command: python
    args:
      - server.py
`;
    fs.writeFileSync(path.join(tmpDir, 'mcp-config.yaml'), yamlContent);
    const result = await mcpConfigAuditor.scan(tmpDir);
    expect(result.findings.some(f => f.title.includes('python'))).toBe(true);
  });

  test('scan() skips package.json', async () => {
    const pkg = { name: 'test', version: '1.0', mcpServers: { s: { command: 'bash' } } };
    fs.writeFileSync(path.join(tmpDir, 'package.json'), JSON.stringify(pkg));
    const result = await mcpConfigAuditor.scan(tmpDir);
    // package.json should be skipped
    expect(result.findings.some(f => f.title.includes('bash'))).toBe(false);
  });

  test('scan() skips tsconfig.json', async () => {
    fs.writeFileSync(path.join(tmpDir, 'tsconfig.json'), JSON.stringify({ compilerOptions: {} }));
    const result = await mcpConfigAuditor.scan(tmpDir);
    expect(result.findings.length).toBe(0);
  });

  test('scan() skips unreadable files without crashing', async () => {
    const filePath = path.join(tmpDir, 'config.json');
    fs.writeFileSync(filePath, '{"mcpServers": {}}');
    fs.chmodSync(filePath, 0o000);

    const result = await mcpConfigAuditor.scan(tmpDir);
    expect(result.scanner).toBe('MCP Config Auditor');

    fs.chmodSync(filePath, 0o644);
  });

  test('scan() handles invalid JSON gracefully', async () => {
    fs.writeFileSync(path.join(tmpDir, 'config.json'), 'not valid json {{{');
    const result = await mcpConfigAuditor.scan(tmpDir);
    expect(result.scanner).toBe('MCP Config Auditor');
    // No findings from invalid JSON
  });

  test('scan() detects URL with credentials', async () => {
    const config = {
      mcpServers: {
        db: { command: 'tool', env: { URL: 'https://user:pass@host.com/db' } },
      },
    };
    fs.writeFileSync(path.join(tmpDir, 'mcp-config.json'), JSON.stringify(config));
    const result = await mcpConfigAuditor.scan(tmpDir);
    expect(result.findings.some(f => f.title.includes('embedded credentials'))).toBe(true);
  });

  test('scan() handles yml extension', async () => {
    const yamlContent = `
mcpServers:
  srv:
    command: node
`;
    fs.writeFileSync(path.join(tmpDir, 'config.yml'), yamlContent);
    const result = await mcpConfigAuditor.scan(tmpDir);
    expect(result.findings.some(f => f.title.includes('node'))).toBe(true);
  });
});

describe('MCP Config Auditor — auditConfig additional coverage', () => {
  test('detects URL with embedded credentials in nested config', () => {
    const config = {
      database: {
        url: 'https://admin:secret123@db.example.com:5432/mydb',
      },
    };
    const findings = auditConfig(config, 'config.json');
    expect(findings.some(f => f.id === 'MCP-URL-CREDS')).toBe(true);
  });

  test('mcp_servers key variant works', () => {
    const config = {
      mcp_servers: {
        s: { command: 'bash' },
      },
    };
    const findings = auditConfig(config, 'test.json');
    expect(findings.some(f => f.title.includes('bash'))).toBe(true);
  });

  test('server without command or tools does not flag missing allowlist', () => {
    const config = {
      mcpServers: {
        s: { env: { NODE_ENV: 'production' } },
      },
    };
    const findings = auditConfig(config, 'test.json');
    expect(findings.some(f => f.title.includes('lacks allowlist'))).toBe(false);
  });

  test('server tools with dangerous permissions in nested tools', () => {
    const config = {
      mcpServers: {
        s: {
          command: 'tool',
          tools: [
            { name: 'exec_shell', permissions: ['*'] },
          ],
        },
      },
    };
    const findings = auditConfig(config, 'test.json');
    expect(findings.some(f => f.title.includes('Dangerous tool') || f.title.includes('dangerous permission'))).toBe(true);
  });
});
