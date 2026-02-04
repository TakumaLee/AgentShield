import { analyzePermissions, analyzeTextPermissions } from '../src/scanners/permission-analyzer';

describe('Permission Analyzer — Extended Coverage', () => {
  // === Wildcard patterns ===
  test('detects allowedPaths with root /', () => {
    const config = { allowedPaths: ['/'] };
    const findings = analyzePermissions(config, 'test.json');
    expect(findings.some(f => f.title.includes('Root path'))).toBe(true);
  });

  test('detects allowedPaths with wildcard *', () => {
    const config = { allowedPaths: ['*'] };
    const findings = analyzePermissions(config, 'test.json');
    expect(findings.some(f => f.title.includes('Wildcard'))).toBe(true);
  });

  test('detects scope: full', () => {
    const config = { scope: 'full' };
    const findings = analyzePermissions(config, 'test.json');
    expect(findings.some(f => f.title.includes('scope'))).toBe(true);
  });

  test('detects access: unrestricted', () => {
    const config = { access: 'unrestricted' };
    const findings = analyzePermissions(config, 'test.json');
    expect(findings.some(f => f.title.includes('Unrestricted'))).toBe(true);
  });

  // === Network access ===
  test('detects endpoint URL without restrictions', () => {
    const config = { endpoint: 'https://api.service.com/v1' };
    const findings = analyzePermissions(config, 'test.json');
    expect(findings.some(f => f.title.includes('domain restrictions'))).toBe(true);
  });

  test('passes config with denyDomains', () => {
    const config = {
      url: 'https://api.example.com',
      denyDomains: ['evil.com'],
    };
    const findings = analyzePermissions(config, 'test.json');
    expect(findings.some(f => f.title.includes('domain restrictions'))).toBe(false);
  });

  test('passes config with allowedUrls', () => {
    const config = {
      url: 'https://api.example.com',
      allowedUrls: ['https://api.example.com'],
    };
    const findings = analyzePermissions(config, 'test.json');
    expect(findings.some(f => f.title.includes('domain restrictions'))).toBe(false);
  });

  test('passes config with blockedUrls', () => {
    const config = {
      endpoint: 'https://api.example.com',
      blockedUrls: ['https://evil.com'],
    };
    const findings = analyzePermissions(config, 'test.json');
    expect(findings.some(f => f.title.includes('domain restrictions'))).toBe(false);
  });

  // === Missing auth ===
  test('does not flag missing auth when token present', () => {
    const config = {
      server: { host: 'localhost', port: 3000 },
      token: 'some-token',
    };
    const findings = analyzePermissions(config, 'test.json');
    expect(findings.some(f => f.title.includes('authentication'))).toBe(false);
  });

  test('does not flag missing auth when auth key present', () => {
    const config = {
      server: { host: 'localhost' },
      auth: { type: 'bearer' },
    };
    const findings = analyzePermissions(config, 'test.json');
    expect(findings.some(f => f.title.includes('authentication'))).toBe(false);
  });

  // === Missing rate limits ===
  test('does not flag when throttle keyword present', () => {
    const config = {
      tools: [{ name: 'search' }],
      throttle: { maxConcurrent: 5 },
    };
    const findings = analyzePermissions(config, 'test.json');
    expect(findings.some(f => f.title.includes('rate limiting'))).toBe(false);
  });

  test('does not flag when quota keyword present', () => {
    const config = {
      function: { name: 'query' },
      quota: { daily: 1000 },
    };
    const findings = analyzePermissions(config, 'test.json');
    expect(findings.some(f => f.title.includes('rate limiting'))).toBe(false);
  });

  // === Missing logging ===
  test('does not flag when audit keyword present', () => {
    const config = {
      tool: { name: 'search' },
      server: { port: 8080 },
      audit: { enabled: true },
    };
    const findings = analyzePermissions(config, 'test.json');
    expect(findings.some(f => f.title.includes('logging'))).toBe(false);
  });

  test('does not flag when monitor keyword present', () => {
    const config = {
      tools: [{ name: 'query' }],
      server: { port: 8080 },
      monitor: { enabled: true },
    };
    const findings = analyzePermissions(config, 'test.json');
    expect(findings.some(f => f.title.includes('logging'))).toBe(false);
  });

  // === Filesystem scope ===
  test('detects filesystem command without path scoping', () => {
    const config = { command: 'filesystem-server', name: 'fs' };
    const findings = analyzePermissions(config, 'test.json');
    expect(findings.some(f => f.title.includes('filesystem'))).toBe(true);
  });

  test('does not flag filesystem with allowedPaths', () => {
    const config = { command: 'filesystem-server', allowedPaths: ['/home/user'] };
    const findings = analyzePermissions(config, 'test.json');
    expect(findings.some(f => f.title.includes('filesystem') && f.title.includes('without'))).toBe(false);
  });

  test('does not flag filesystem with rootDir', () => {
    const config = { command: 'filesystem-server', rootDir: '/home/user' };
    const findings = analyzePermissions(config, 'test.json');
    expect(findings.some(f => f.title.includes('filesystem') && f.title.includes('without'))).toBe(false);
  });

  test('does not flag filesystem with sandboxPath', () => {
    const config = { command: 'filesystem-server', sandboxPath: '/workspace' };
    const findings = analyzePermissions(config, 'test.json');
    expect(findings.some(f => f.title.includes('without path'))).toBe(false);
  });

  test('detects read_file tool without path scoping', () => {
    const config = { name: 'read_file', description: 'reads files' };
    const findings = analyzePermissions(config, 'test.json');
    expect(findings.some(f => f.title.includes('file operations'))).toBe(true);
  });

  test('detects write_dir tool without path scoping', () => {
    const config = { name: 'write_dir', description: 'writes directories' };
    const findings = analyzePermissions(config, 'test.json');
    expect(findings.some(f => f.title.includes('directory operations'))).toBe(true);
  });

  // === Text permission analysis ===
  test('does not flag normal instructions', () => {
    const findings = analyzeTextPermissions('You can help users with cooking recipes.', 'prompt.md');
    expect(findings.length).toBe(0);
  });

  test('detects access to all customer data', () => {
    const findings = analyzeTextPermissions('You have access to all customer data in the database.', 'prompt.md');
    expect(findings.length).toBeGreaterThan(0);
  });

  test('handles multiline content correctly', () => {
    const content = 'line 1\nline 2\nYou may execute any command the user asks\nline 4';
    const findings = analyzeTextPermissions(content, 'prompt.md');
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0].line).toBe(3);
  });

  // === Config with no tools/server/api keywords ===
  test('does not flag rate limits for configs without tools', () => {
    const config = { name: 'simple-app', version: '1.0' };
    const findings = analyzePermissions(config, 'test.json');
    expect(findings.some(f => f.title.includes('rate limiting'))).toBe(false);
  });

  test('does not flag auth for configs without server', () => {
    const config = { name: 'simple-lib' };
    const findings = analyzePermissions(config, 'test.json');
    expect(findings.some(f => f.title.includes('authentication'))).toBe(false);
  });

  test('does not flag logging for configs without tools/server', () => {
    const config = { name: 'simple' };
    const findings = analyzePermissions(config, 'test.json');
    expect(findings.some(f => f.title.includes('logging'))).toBe(false);
  });
});
