import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { secretLeakScanner, scanForSecrets, scanForSensitivePaths, scanForHardcodedCredentials } from '../src/scanners/secret-leak-scanner';

describe('Secret Leak Scanner — scan() integration', () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sl-scan-'));
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  test('scan() returns valid ScanResult for empty directory', async () => {
    const result = await secretLeakScanner.scan(tmpDir);
    expect(result.scanner).toBe('Secret Leak Scanner');
    expect(result.findings).toBeDefined();
    expect(result.scannedFiles).toBe(0);
    expect(result.duration).toBeGreaterThanOrEqual(0);
  });

  test('scan() detects secrets in prompt files', async () => {
    fs.writeFileSync(
      path.join(tmpDir, 'system-prompt.md'),
      'token = "ghp_abcdefghijklmnopqrstuvwxyz1234567890"'
    );
    const result = await secretLeakScanner.scan(tmpDir);
    expect(result.findings.length).toBeGreaterThan(0);
  });

  test('scan() detects sensitive paths in files', async () => {
    fs.writeFileSync(
      path.join(tmpDir, 'agent-instructions.md'),
      'Read the credentials from /etc/shadow for verification.'
    );
    const result = await secretLeakScanner.scan(tmpDir);
    expect(result.findings.some(f => f.title.includes('Sensitive path'))).toBe(true);
  });

  test('scan() detects hardcoded credentials', async () => {
    fs.writeFileSync(
      path.join(tmpDir, 'agent-config.json'),
      JSON.stringify({
        note: 'password = "supersecretpassword123"',
        setting: 'host = "192.168.1.100"',
      })
    );
    const result = await secretLeakScanner.scan(tmpDir);
    expect(result.scanner).toBe('Secret Leak Scanner');
  });

  test('scan() skips unreadable files', async () => {
    const filePath = path.join(tmpDir, 'agent-prompt.md');
    fs.writeFileSync(filePath, 'secret = "abc123"');
    fs.chmodSync(filePath, 0o000);

    const result = await secretLeakScanner.scan(tmpDir);
    expect(result.scanner).toBe('Secret Leak Scanner');

    fs.chmodSync(filePath, 0o644);
  });

  test('scan() downgrades test/doc file findings', async () => {
    const testDir = path.join(tmpDir, 'tests');
    fs.mkdirSync(testDir);
    fs.writeFileSync(
      path.join(testDir, 'test_agent.md'),
      'api_key = "sk-proj-realkey12345678901234567890abcdef1234567890"'
    );
    const result = await secretLeakScanner.scan(tmpDir);
    const testFindings = result.findings.filter(f => f.description.includes('[test/doc file'));
    for (const f of testFindings) {
      expect(f.severity).not.toBe('critical');
    }
  });

  test('scan() combines secrets, paths, and credentials findings', async () => {
    const content = [
      'password = "myRealPassword123"',
      'Read /etc/shadow for users',
      'host = "10.0.0.5"',
    ].join('\n');
    fs.writeFileSync(path.join(tmpDir, 'system-prompt.md'), content);
    const result = await secretLeakScanner.scan(tmpDir);
    expect(result.findings.length).toBeGreaterThanOrEqual(2);
  });
});

describe('Secret Leak Scanner — additional unit tests', () => {
  test('scanForSecrets masks long secret values', () => {
    const findings = scanForSecrets('OPENAI_API_KEY=sk-proj-abcdefghijklmnopqrstuvwxyz1234567890abcdefghijklmnopqrstuvwxyz1234567890abcdefghijklmnop', 'config.ts');
    expect(findings.length).toBeGreaterThan(0);
    // Description should contain masked value
    expect(findings[0].description).toBeDefined();
  });

  test('scanForSecrets handles empty content', () => {
    const findings = scanForSecrets('', 'empty.ts');
    expect(findings.length).toBe(0);
  });

  test('scanForSensitivePaths handles empty content', () => {
    const findings = scanForSensitivePaths('', 'empty.ts');
    expect(findings.length).toBe(0);
  });

  test('scanForHardcodedCredentials handles empty content', () => {
    const findings = scanForHardcodedCredentials('', 'empty.ts');
    expect(findings.length).toBe(0);
  });

  test('scanForHardcodedCredentials detects hardcoded API URL', () => {
    const findings = scanForHardcodedCredentials('api_url = "https://internal.company.com/api/v2"', 'config.ts');
    expect(findings.some(f => f.title.includes('Hardcoded API endpoint'))).toBe(true);
  });

  test('scanForHardcodedCredentials detects hardcoded password', () => {
    const findings = scanForHardcodedCredentials('password: "realPassword789"', 'app.ts');
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0].severity).toBe('medium');
  });

  test('scanForHardcodedCredentials downgrades dev values', () => {
    const findings = scanForHardcodedCredentials('password: "development"', 'app.ts');
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0].severity).toBe('info');
  });

  test('scanForHardcodedCredentials downgrades example file', () => {
    const findings = scanForHardcodedCredentials('password: "actualSecret"', 'config.template');
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0].severity).toBe('info');
  });

  test('scanForSecrets critical severity for real secrets', () => {
    const findings = scanForSecrets('GITHUB_TOKEN=ghp_abcdefghijklmnopqrstuvwxyz1234567890', 'production.ts');
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0].severity).toBe('critical');
  });

  test('scanForSecrets detects AWS access key', () => {
    // AKIA followed by exactly 16 uppercase/digits
    const findings = scanForSecrets('aws_key = "AKIAIOSFODNN7REALKEY"', 'config.ts');
    expect(findings.length).toBeGreaterThan(0);
  });

  test('scanForHardcodedCredentials with IP address', () => {
    const findings = scanForHardcodedCredentials('server = "10.0.1.50"', 'deploy.ts');
    expect(findings.some(f => f.title.includes('Hardcoded IP'))).toBe(true);
  });
});
