import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { secretLeakScanner } from '../src/scanners/secret-leak-scanner';
import { skillAuditor } from '../src/scanners/skill-auditor';
import { permissionAnalyzer } from '../src/scanners/permission-analyzer';
import { auditSkillContent, applyFrameworkDowngrades } from '../src/scanners/skill-auditor';
import {
  isCredentialManagementFile,
  isFrameworkInfraFile,
  isUserInputFile,
  isSkillPluginFile,
  hasAuthFiles,
} from '../src/utils/file-utils';

// === File classification helpers ===

describe('Context-aware file classification', () => {
  test('isCredentialManagementFile identifies credential files', () => {
    expect(isCredentialManagementFile('/project/src/auth.ts')).toBe(true);
    expect(isCredentialManagementFile('/project/src/credentials.ts')).toBe(true);
    expect(isCredentialManagementFile('/project/lib/token.ts')).toBe(true);
    expect(isCredentialManagementFile('/project/src/accounts.ts')).toBe(true);
    expect(isCredentialManagementFile('/project/src/auth-store.ts')).toBe(true);
    expect(isCredentialManagementFile('/project/src/key-manager.ts')).toBe(true);
    expect(isCredentialManagementFile('/project/src/secret-manager.ts')).toBe(true);
    expect(isCredentialManagementFile('/project/src/vault.ts')).toBe(true);
  });

  test('isCredentialManagementFile rejects non-credential files', () => {
    expect(isCredentialManagementFile('/project/src/index.ts')).toBe(false);
    expect(isCredentialManagementFile('/project/src/utils.ts')).toBe(false);
    expect(isCredentialManagementFile('/project/src/server.ts')).toBe(false);
  });

  test('isFrameworkInfraFile identifies framework dirs', () => {
    expect(isFrameworkInfraFile('/project/src/foo.ts')).toBe(true);
    expect(isFrameworkInfraFile('/project/lib/bar.ts')).toBe(true);
    expect(isFrameworkInfraFile('/project/core/baz.ts')).toBe(true);
    expect(isFrameworkInfraFile('/project/internal/qux.ts')).toBe(true);
    expect(isFrameworkInfraFile('/project/utils/helper.ts')).toBe(true);
    expect(isFrameworkInfraFile('/project/extensions/ext.ts')).toBe(true);
  });

  test('isUserInputFile identifies input handler files', () => {
    expect(isUserInputFile('/project/src/handler.ts')).toBe(true);
    expect(isUserInputFile('/project/src/my-controller.ts')).toBe(true);
    expect(isUserInputFile('/project/src/api/route.ts')).toBe(true);
    expect(isUserInputFile('/project/src/endpoint.ts')).toBe(true);
    expect(isUserInputFile('/project/src/parse-input.ts')).toBe(true);
  });

  test('isUserInputFile rejects non-input files', () => {
    expect(isUserInputFile('/project/src/utils.ts')).toBe(false);
    expect(isUserInputFile('/project/src/index.ts')).toBe(false);
  });

  test('isSkillPluginFile identifies skill/plugin dirs', () => {
    expect(isSkillPluginFile('/project/skills/my-skill.ts')).toBe(true);
    expect(isSkillPluginFile('/project/plugins/my-plugin.ts')).toBe(true);
  });

  test('isSkillPluginFile rejects non-skill files', () => {
    expect(isSkillPluginFile('/project/src/core.ts')).toBe(false);
    expect(isSkillPluginFile('/project/lib/utils.ts')).toBe(false);
  });

  test('hasAuthFiles detects auth-related files', () => {
    expect(hasAuthFiles(['/project/src/auth.ts', '/project/src/index.ts'])).toBe(true);
    expect(hasAuthFiles(['/project/src/credentials.ts'])).toBe(true);
    expect(hasAuthFiles(['/project/src/pairing.ts'])).toBe(true);
    expect(hasAuthFiles(['/project/src/index.ts', '/project/src/server.ts'])).toBe(false);
  });
});

// === Secret Leak Scanner with context ===

describe('Secret Leak Scanner — framework context', () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ctx-secret-'));
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  test('credential management files get downgraded to info in framework context', async () => {
    // Create a credential management file with a secret pattern
    const authFile = path.join(tmpDir, 'auth.ts');
    fs.writeFileSync(authFile, `
const api_key = "sk-real-secret-key-1234567890abcdef";
const password = "super_secret_password_123";
    `);

    // Scan with framework context
    const frameworkResult = await secretLeakScanner.scan(tmpDir, { context: 'framework' });
    const frameworkFindings = frameworkResult.findings.filter(f => f.file === authFile);

    // All findings from auth.ts should be info
    for (const f of frameworkFindings) {
      expect(f.severity).toBe('info');
      expect(f.description).toContain('Credential management module');
    }

    // Scan with default context (app)
    const appResult = await secretLeakScanner.scan(tmpDir, { context: 'app' });
    const appFindings = appResult.findings.filter(f => f.file === authFile);

    // App context should NOT downgrade
    const hasNonInfo = appFindings.some(f => f.severity !== 'info');
    expect(hasNonInfo).toBe(true);
  });

  test('non-credential files are NOT downgraded in framework context', async () => {
    const normalFile = path.join(tmpDir, 'server.ts');
    fs.writeFileSync(normalFile, `
const api_key = "sk-real-secret-key-1234567890abcdef";
    `);

    const result = await secretLeakScanner.scan(tmpDir, { context: 'framework' });
    const findings = result.findings.filter(f => f.file === normalFile);

    // Should NOT be downgraded (not a credential management file)
    const hasCriticalOrHigh = findings.some(f => f.severity === 'critical' || f.severity === 'high');
    expect(hasCriticalOrHigh).toBe(true);
  });
});

// === Skill Auditor with context ===

describe('Skill Auditor — framework context downgrades', () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ctx-skill-'));
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  test('path traversal downgraded in framework infra files', () => {
    const content = `readFileSync("../../config/settings.json")`;
    const filePath = '/project/src/config-loader.ts';
    const findings = auditSkillContent(content, filePath);
    applyFrameworkDowngrades(findings, filePath);

    const traversalFindings = findings.filter(f => f.id.startsWith('SA-006'));
    for (const f of traversalFindings) {
      expect(f.severity).toBe('medium');
      expect(f.description).toContain('Framework infrastructure file');
    }
  });

  test('path traversal NOT downgraded in user input handler files', () => {
    const content = `readFileSync("../../" + userInput)`;
    const filePath = '/project/src/handler.ts';  // user-input file
    const findings = auditSkillContent(content, filePath);
    applyFrameworkDowngrades(findings, filePath);

    const traversalFindings = findings.filter(f => f.id.startsWith('SA-006'));
    for (const f of traversalFindings) {
      expect(f.severity).toBe('high'); // NOT downgraded
    }
  });

  test('shell execution downgraded in core framework files', () => {
    const content = `import { exec } from 'child_process';`;
    const filePath = '/project/src/exec-runner.ts';
    const findings = auditSkillContent(content, filePath);
    applyFrameworkDowngrades(findings, filePath);

    const shellFindings = findings.filter(f => f.id.startsWith('SA-003d'));
    for (const f of shellFindings) {
      expect(f.severity).toBe('info');
      expect(f.description).toContain('Framework-level shell capability');
    }
  });

  test('shell execution NOT downgraded in skill/plugin directories', () => {
    const content = `import { exec } from 'child_process';`;
    const filePath = '/project/skills/my-skill/index.ts';
    const findings = auditSkillContent(content, filePath);
    applyFrameworkDowngrades(findings, filePath);

    const shellFindings = findings.filter(f => f.id.startsWith('SA-003d'));
    for (const f of shellFindings) {
      expect(f.severity).toBe('medium'); // NOT downgraded
    }
  });

  test('.env reading downgraded for standard file reads', () => {
    const content = `readFileSync(".env")`;
    const filePath = '/project/src/config.ts';
    const findings = auditSkillContent(content, filePath);

    // SA-002 should match (reading sensitive file with .env)
    const envFindings = findings.filter(f => f.id.startsWith('SA-002-') && f.title === 'Reading sensitive file');
    expect(envFindings.length).toBeGreaterThan(0);

    applyFrameworkDowngrades(findings, filePath);

    for (const f of envFindings) {
      expect(f.severity).toBe('info');
      expect(f.description).toContain('12-factor app pattern');
    }
  });

  test('scan() with framework context applies downgrades', async () => {
    const srcDir = path.join(tmpDir, 'src');
    fs.mkdirSync(srcDir);
    fs.writeFileSync(path.join(srcDir, 'runner.ts'), `import { spawn } from 'child_process';`);

    const frameworkResult = await skillAuditor.scan(tmpDir, { context: 'framework' });
    const shellFindings = frameworkResult.findings.filter(f => f.id.startsWith('SA-003d'));

    for (const f of shellFindings) {
      expect(f.severity).toBe('info');
    }

    // Compare with app context
    const appResult = await skillAuditor.scan(tmpDir, { context: 'app' });
    const appShellFindings = appResult.findings.filter(f => f.id.startsWith('SA-003d'));

    for (const f of appShellFindings) {
      expect(f.severity).toBe('medium'); // NOT downgraded
    }
  });

  test('scan() with skill context does NOT apply downgrades', async () => {
    const srcDir = path.join(tmpDir, 'src');
    fs.mkdirSync(srcDir);
    fs.writeFileSync(path.join(srcDir, 'runner.ts'), `import { spawn } from 'child_process';`);

    const result = await skillAuditor.scan(tmpDir, { context: 'skill' });
    const shellFindings = result.findings.filter(f => f.id.startsWith('SA-003d'));

    for (const f of shellFindings) {
      expect(f.severity).toBe('medium'); // Strict — no downgrades
    }
  });
});

// === Permission Analyzer with context ===

describe('Permission Analyzer — framework context', () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ctx-perm-'));
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  test('"No authentication configured" downgraded when auth files exist', async () => {
    // Create a config file that triggers "No authentication configured"
    fs.writeFileSync(
      path.join(tmpDir, 'server-config.json'),
      JSON.stringify({ server: { endpoint: "https://api.example.com", port: 3000 } })
    );
    // Create an auth file so the project "has auth"
    fs.writeFileSync(path.join(tmpDir, 'auth.ts'), `export function authenticate() {}`);

    const frameworkResult = await permissionAnalyzer.scan(tmpDir, { context: 'framework' });
    const noAuthFindings = frameworkResult.findings.filter(f => f.title === 'No authentication configured');

    for (const f of noAuthFindings) {
      expect(f.severity).toBe('info');
      expect(f.description).toContain('Authentication modules detected');
    }
  });

  test('"No authentication configured" NOT downgraded when no auth files', async () => {
    // Config with no auth files in the project
    fs.writeFileSync(
      path.join(tmpDir, 'server-config.json'),
      JSON.stringify({ server: { endpoint: "https://api.example.com", port: 3000 } })
    );

    const result = await permissionAnalyzer.scan(tmpDir, { context: 'framework' });
    const noAuthFindings = result.findings.filter(f => f.title === 'No authentication configured');

    for (const f of noAuthFindings) {
      expect(f.severity).toBe('high'); // NOT downgraded
    }
  });

  test('"No authentication configured" NOT downgraded in app context', async () => {
    fs.writeFileSync(
      path.join(tmpDir, 'server-config.json'),
      JSON.stringify({ server: { endpoint: "https://api.example.com", port: 3000 } })
    );
    fs.writeFileSync(path.join(tmpDir, 'auth.ts'), `export function authenticate() {}`);

    const result = await permissionAnalyzer.scan(tmpDir, { context: 'app' });
    const noAuthFindings = result.findings.filter(f => f.title === 'No authentication configured');

    for (const f of noAuthFindings) {
      expect(f.severity).toBe('high'); // NOT downgraded in app context
    }
  });
});

// === Context flag integration ===

describe('--context flag integration', () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ctx-flag-'));
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  test('context option is passed through to scanners', async () => {
    const srcDir = path.join(tmpDir, 'src');
    fs.mkdirSync(srcDir);
    fs.writeFileSync(path.join(srcDir, 'exec.ts'), `import { exec } from 'child_process';`);

    // framework context
    const fw = await skillAuditor.scan(tmpDir, { context: 'framework' });
    const fwShell = fw.findings.filter(f => f.id.startsWith('SA-003d'));
    expect(fwShell.every(f => f.severity === 'info')).toBe(true);

    // skill context (strict)
    const sk = await skillAuditor.scan(tmpDir, { context: 'skill' });
    const skShell = sk.findings.filter(f => f.id.startsWith('SA-003d'));
    expect(skShell.every(f => f.severity === 'medium')).toBe(true);

    // app context (default, no downgrades)
    const ap = await skillAuditor.scan(tmpDir, { context: 'app' });
    const apShell = ap.findings.filter(f => f.id.startsWith('SA-003d'));
    expect(apShell.every(f => f.severity === 'medium')).toBe(true);
  });
});
