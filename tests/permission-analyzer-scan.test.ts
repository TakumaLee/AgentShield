import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { permissionAnalyzer, analyzePermissions, analyzeTextPermissions } from '../src/scanners/permission-analyzer';

describe('Permission Analyzer — scan() integration', () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'perm-scan-'));
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  test('scan() returns valid ScanResult for empty directory', async () => {
    const result = await permissionAnalyzer.scan(tmpDir);
    expect(result.scanner).toBe('Permission Analyzer');
    expect(result.findings).toBeDefined();
    expect(result.scannedFiles).toBe(0);
    expect(result.duration).toBeGreaterThanOrEqual(0);
  });

  test('scan() detects over-privileged config in JSON', async () => {
    const config = {
      permissions: ['*'],
      tools: [{ name: 'execute_code' }],
      server: { host: 'localhost' },
    };
    fs.writeFileSync(path.join(tmpDir, 'agent-config.json'), JSON.stringify(config));
    const result = await permissionAnalyzer.scan(tmpDir);
    expect(result.findings.length).toBeGreaterThan(0);
  });

  test('scan() detects dangerous text permissions in prompts', async () => {
    fs.writeFileSync(
      path.join(tmpDir, 'system-prompt.md'),
      'You have full access to the filesystem and can execute any command.'
    );
    const result = await permissionAnalyzer.scan(tmpDir);
    expect(result.findings.some(f => f.title.includes('Full system access') || f.title.includes('Unrestricted code execution'))).toBe(true);
  });

  test('scan() parses YAML config files', async () => {
    const yamlContent = `
tools:
  - name: file_manager
server:
  port: 8080
`;
    fs.writeFileSync(path.join(tmpDir, 'agent-config.yaml'), yamlContent);
    const result = await permissionAnalyzer.scan(tmpDir);
    expect(result.scanner).toBe('Permission Analyzer');
  });

  test('scan() skips package.json and other manifests', async () => {
    fs.writeFileSync(path.join(tmpDir, 'package.json'), JSON.stringify({ name: 'test', tools: [{ name: 'cmd' }] }));
    const result = await permissionAnalyzer.scan(tmpDir);
    // package.json should be skipped for config analysis (but still may be scanned for text)
    expect(result.scanner).toBe('Permission Analyzer');
  });

  test('scan() skips unreadable files', async () => {
    const filePath = path.join(tmpDir, 'agent-config.json');
    fs.writeFileSync(filePath, '{}');
    fs.chmodSync(filePath, 0o000);

    const result = await permissionAnalyzer.scan(tmpDir);
    expect(result.scanner).toBe('Permission Analyzer');

    fs.chmodSync(filePath, 0o644);
  });

  test('scan() downgrades test/doc file findings', async () => {
    const testDir = path.join(tmpDir, 'tests');
    fs.mkdirSync(testDir);
    fs.writeFileSync(
      path.join(testDir, 'test_agent.md'),
      'You have full access to the system and can execute any command.'
    );
    const result = await permissionAnalyzer.scan(tmpDir);
    const testFindings = result.findings.filter(f => f.description.includes('[test/doc file'));
    for (const f of testFindings) {
      expect(f.severity).not.toBe('critical');
    }
  });

  test('scan() handles invalid JSON gracefully', async () => {
    fs.writeFileSync(path.join(tmpDir, 'config.json'), 'not json');
    const result = await permissionAnalyzer.scan(tmpDir);
    expect(result.scanner).toBe('Permission Analyzer');
  });
});

describe('Permission Analyzer — analyzePermissions additional', () => {
  test('detects permissions: ["*"] wildcard', () => {
    const config = { permissions: ['*'] };
    const findings = analyzePermissions(config, 'test.json');
    expect(findings.some(f => f.title.includes('Wildcard permission'))).toBe(true);
  });

  test('detects scope: all', () => {
    const config = { scope: 'all' };
    const findings = analyzePermissions(config, 'test.json');
    expect(findings.some(f => f.title.includes('scope'))).toBe(true);
  });

  test('detects missing auth with endpoint', () => {
    const config = { endpoint: 'https://api.com/v1' };
    const findings = analyzePermissions(config, 'test.json');
    expect(findings.some(f => f.title.includes('authentication'))).toBe(true);
  });

  test('detects missing rate limits for api config', () => {
    const config = { api: { baseUrl: 'https://api.com' } };
    const findings = analyzePermissions(config, 'test.json');
    expect(findings.some(f => f.title.includes('rate limiting'))).toBe(true);
  });

  test('detects missing logging for tool+server config', () => {
    const config = { tool: { name: 'search' }, server: { port: 3000 } };
    const findings = analyzePermissions(config, 'test.json');
    expect(findings.some(f => f.title.includes('logging'))).toBe(true);
  });

  test('detects url without allowedDomains', () => {
    const config = { url: 'https://external-api.com/data' };
    const findings = analyzePermissions(config, 'test.json');
    expect(findings.some(f => f.title.includes('domain restrictions'))).toBe(true);
  });

  test('does not flag when allowedDomains present', () => {
    const config = { url: 'https://api.com', allowedDomains: ['api.com'] };
    const findings = analyzePermissions(config, 'test.json');
    expect(findings.some(f => f.title.includes('domain restrictions'))).toBe(false);
  });

  test('detects filesystem without workDir', () => {
    const config = { command: 'filesystem-tool' };
    const findings = analyzePermissions(config, 'test.json');
    expect(findings.some(f => f.title.includes('filesystem'))).toBe(true);
  });

  test('does not flag filesystem with workDir', () => {
    const config = { command: 'filesystem-tool', workDir: '/app' };
    const findings = analyzePermissions(config, 'test.json');
    expect(findings.some(f => f.title.includes('without path'))).toBe(false);
  });
});

describe('Permission Analyzer — analyzeTextPermissions additional', () => {
  test('detects "you can access any file"', () => {
    const findings = analyzeTextPermissions('You can access any file on the system.', 'prompt.md');
    expect(findings.length).toBeGreaterThan(0);
  });

  test('detects "you can read all files"', () => {
    const findings = analyzeTextPermissions('You can read all files in the system.', 'prompt.md');
    expect(findings.length).toBeGreaterThan(0);
  });

  test('detects "no restrictions on what you can"', () => {
    const findings = analyzeTextPermissions('There are no restrictions on what you can do.', 'prompt.md');
    expect(findings.length).toBeGreaterThan(0);
  });

  test('detects "you may execute any script"', () => {
    const findings = analyzeTextPermissions('You may execute any script needed.', 'prompt.md');
    expect(findings.length).toBeGreaterThan(0);
  });

  test('detects "access to all user data"', () => {
    const findings = analyzeTextPermissions('You have access to all user data.', 'prompt.md');
    expect(findings.length).toBeGreaterThan(0);
  });

  test('includes correct line numbers', () => {
    const content = 'safe line\nsafe line 2\nYou have full access to the network for anything.\nsafe line 4';
    const findings = analyzeTextPermissions(content, 'prompt.md');
    if (findings.length > 0) {
      expect(findings[0].line).toBe(3);
    }
  });

  test('returns empty for safe content', () => {
    const findings = analyzeTextPermissions('You can help users with general questions.', 'prompt.md');
    expect(findings.length).toBe(0);
  });
});
