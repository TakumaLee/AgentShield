import { scanForSecrets, scanForSensitivePaths, scanForHardcodedCredentials } from '../src/scanners/secret-leak-scanner';

describe('Secret Leak Scanner — Extended Coverage', () => {
  // === Secret patterns edge cases ===
  test('detects PostgreSQL connection string', () => {
    const findings = scanForSecrets('DB_URL=postgresql://user:pass@host:5432/db');
    expect(findings.length).toBeGreaterThan(0);
  });

  test('detects MySQL connection string', () => {
    const findings = scanForSecrets('DB_URL=mysql://user:pass@host:3306/db');
    expect(findings.length).toBeGreaterThan(0);
  });

  test('detects Redis connection string', () => {
    const findings = scanForSecrets('REDIS_URL=redis://myuser:realpass@prodhost:6379');
    expect(findings.length).toBeGreaterThan(0);
  });

  test('detects JWT token', () => {
    const findings = scanForSecrets('token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"');
    expect(findings.length).toBeGreaterThan(0);
  });

  test('detects Google OAuth client ID', () => {
    const findings = scanForSecrets('client_id = "123456789012-abcdefghijklmnopqrstuvwxyz123456.apps.googleusercontent.com"');
    expect(findings.length).toBeGreaterThan(0);
  });

  // === Placeholder detection ===
  test('does not flag TODO placeholder', () => {
    const findings = scanForSecrets('api_key = "TODO: add real key"');
    expect(findings.length).toBe(0);
  });

  test('does not flag <your-key> placeholder', () => {
    const findings = scanForSecrets('token: "<your-api-token>"');
    expect(findings.length).toBe(0);
  });

  test('does not flag change_me placeholder', () => {
    const findings = scanForSecrets('secret = "change_me_before_deploy"');
    expect(findings.length).toBe(0);
  });

  test('does not flag os.environ reference', () => {
    const findings = scanForSecrets('key = os.environ["API_KEY"]');
    expect(findings.length).toBe(0);
  });

  test('does not flag dummy/mock/fake values', () => {
    const findings = scanForSecrets('token = "dummy_token_for_testing"');
    expect(findings.length).toBe(0);
  });

  test('does not flag template values', () => {
    const findings = scanForSecrets('secret = "template_secret_value"');
    expect(findings.length).toBe(0);
  });

  // === Dev credential detection ===
  test('downgrades dev password (postgres)', () => {
    const findings = scanForSecrets('password = "postgres"');
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0].severity).toBe('medium');
  });

  test('downgrades dev password (admin_user)', () => {
    const findings = scanForSecrets('password: "admin_user"');
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0].severity).toBe('medium');
  });

  // === Example file downgrade ===
  test('downgrades findings in example files', () => {
    const findings = scanForSecrets('password = "realpassword123"', '/project/.env.example');
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0].severity).toBe('info');
  });

  test('downgrades findings in sample files', () => {
    const findings = scanForSecrets('api_key = "sk-realkeyvalue1234567890"', '/project/config.sample');
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0].severity).toBe('info');
  });

  test('downgrades findings in docker-compose files', () => {
    const findings = scanForSecrets('password = "realpassword123"', '/project/docker-compose.yml');
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0].severity).toBe('info');
  });

  // === Sensitive path detection ===
  test('detects /etc/shadow reference', () => {
    const findings = scanForSensitivePaths('Reading /etc/shadow for user hashes');
    expect(findings.length).toBeGreaterThan(0);
  });

  test('detects .ssh/authorized_keys reference', () => {
    const findings = scanForSensitivePaths('Add key to .ssh/authorized_keys');
    expect(findings.length).toBeGreaterThan(0);
  });

  test('detects .env.local reference', () => {
    const findings = scanForSensitivePaths('Load .env.local for local config');
    expect(findings.length).toBeGreaterThan(0);
  });

  test('detects .env.production reference', () => {
    const findings = scanForSensitivePaths('Check .env.production secrets');
    expect(findings.length).toBeGreaterThan(0);
  });

  test('detects /root/ path', () => {
    const findings = scanForSensitivePaths('Access /root/.bashrc');
    expect(findings.length).toBeGreaterThan(0);
  });

  test('detects C:\\Users\\Administrator path', () => {
    const findings = scanForSensitivePaths('C:\\Users\\Administrator\\Desktop');
    expect(findings.length).toBeGreaterThan(0);
  });

  test('detects .docker/config.json', () => {
    const findings = scanForSensitivePaths('Read .docker/config.json for registry auth');
    expect(findings.length).toBeGreaterThan(0);
  });

  test('detects wp-config.php', () => {
    const findings = scanForSensitivePaths('Edit wp-config.php for database settings');
    expect(findings.length).toBeGreaterThan(0);
  });

  test('does not flag normal paths', () => {
    const findings = scanForSensitivePaths('/home/user/documents/report.pdf');
    expect(findings.length).toBe(0);
  });

  // === Hardcoded credentials ===
  test('detects hardcoded username', () => {
    const findings = scanForHardcodedCredentials('username = "dbadmin"');
    expect(findings.length).toBeGreaterThan(0);
  });

  test('downgrades dev credentials (localhost)', () => {
    const findings = scanForHardcodedCredentials('host = "127.0.0.1"');
    // It's a hardcoded IP, but dev credential check depends on value
    expect(findings.length).toBeGreaterThan(0);
  });

  test('detects hardcoded base_url', () => {
    const findings = scanForHardcodedCredentials('base_url = "https://internal.api.company.com/v2"');
    expect(findings.length).toBeGreaterThan(0);
  });

  test('does not flag placeholder credentials', () => {
    const findings = scanForHardcodedCredentials('password = "your_password_here"');
    expect(findings.length).toBe(0);
  });

  test('does not flag FIXME placeholder credentials', () => {
    const findings = scanForHardcodedCredentials('password = "FIXME_SET_REAL_PASSWORD"');
    expect(findings.length).toBe(0);
  });

  test('downgrades dev credential passwords', () => {
    const findings = scanForHardcodedCredentials('password = "root"');
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0].severity).toBe('info');
  });

  test('downgrades example file hardcoded creds', () => {
    const findings = scanForHardcodedCredentials('password = "mysecret"', 'config.example');
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0].severity).toBe('info');
  });

  // === Multi-line content ===
  test('scans all lines for secrets', () => {
    const content = 'line 1\nline 2\napi_key = "sk-realkey12345678901234567890"\nline 4';
    const findings = scanForSecrets(content, 'config.ts');
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0].line).toBe(3);
  });

  test('finds multiple secrets in same content', () => {
    const content = [
      'OPENAI_KEY=sk-12345678901234567890abcdef',
      'GITHUB_TOKEN=ghp_abcdefghijklmnopqrstuvwxyz1234567890',
    ].join('\n');
    const findings = scanForSecrets(content, 'env.ts');
    expect(findings.length).toBeGreaterThanOrEqual(2);
  });
});
