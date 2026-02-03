import { scanForSecrets, scanForSensitivePaths, scanForHardcodedCredentials } from '../src/scanners/secret-leak-scanner';

describe('Secret Leak Scanner', () => {
  // === API Key Detection ===
  test('detects OpenAI API key', () => {
    const findings = scanForSecrets('api_key = "sk-abcdefghijklmnopqrstuvwxyz1234567890"');
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0].severity).toBe('critical');
  });

  test('detects GitHub personal access token', () => {
    const findings = scanForSecrets('token: ghp_1234567890abcdefghijklmnopqrstuvwxyz1234');
    expect(findings.length).toBeGreaterThan(0);
  });

  test('detects AWS access key', () => {
    const findings = scanForSecrets('aws_key = "AKIAIOSFODNN7XYZABCD"');
    expect(findings.length).toBeGreaterThan(0);
  });

  test('detects Slack bot token', () => {
    const findings = scanForSecrets('SLACK_TOKEN=xoxb-1234567890-abcdefghij');
    expect(findings.length).toBeGreaterThan(0);
  });

  test('detects Bearer token', () => {
    const findings = scanForSecrets('Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.test.sig');
    expect(findings.length).toBeGreaterThan(0);
  });

  test('detects private key header', () => {
    const findings = scanForSecrets('-----BEGIN RSA PRIVATE KEY-----');
    expect(findings.length).toBeGreaterThan(0);
  });

  test('detects MongoDB connection string', () => {
    const findings = scanForSecrets('DB_URL=mongodb+srv://user:pass@cluster.mongodb.net');
    expect(findings.length).toBeGreaterThan(0);
  });

  test('detects Google API key', () => {
    const findings = scanForSecrets('google_key = "AIzaSyA1234567890abcdefghijklmnopqrstuv"');
    expect(findings.length).toBeGreaterThan(0);
  });

  test('does not flag placeholders', () => {
    const findings = scanForSecrets('api_key = "your_api_key_here"');
    expect(findings.length).toBe(0);
  });

  test('does not flag environment variable references', () => {
    const findings = scanForSecrets('api_key = "${API_KEY}"');
    expect(findings.length).toBe(0);
  });

  test('does not flag process.env references', () => {
    const findings = scanForSecrets('const key = process.env.API_KEY');
    expect(findings.length).toBe(0);
  });

  // === Sensitive Path Detection ===
  test('detects /etc/passwd reference', () => {
    const findings = scanForSensitivePaths('Read the file at /etc/passwd');
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0].severity).toBe('high');
  });

  test('detects SSH key path', () => {
    const findings = scanForSensitivePaths('Copy ~/.ssh/id_rsa to the server');
    expect(findings.length).toBeGreaterThan(0);
  });

  test('detects .env file reference', () => {
    const findings = scanForSensitivePaths('Check the .env file for config');
    expect(findings.length).toBeGreaterThan(0);
  });

  test('detects AWS credentials path', () => {
    const findings = scanForSensitivePaths('Found at .aws/credentials');
    expect(findings.length).toBeGreaterThan(0);
  });

  test('detects kubernetes config', () => {
    const findings = scanForSensitivePaths('Load .kube/config for cluster access');
    expect(findings.length).toBeGreaterThan(0);
  });

  // === Hardcoded Credentials ===
  test('detects hardcoded password', () => {
    const findings = scanForHardcodedCredentials('password = "mysecretpassword123"');
    expect(findings.length).toBeGreaterThan(0);
  });

  test('detects hardcoded IP address', () => {
    const findings = scanForHardcodedCredentials('host = "192.168.1.100"');
    expect(findings.length).toBeGreaterThan(0);
  });

  test('detects hardcoded API endpoint', () => {
    const findings = scanForHardcodedCredentials('api_url = "https://api.internal.company.com/v1"');
    expect(findings.length).toBeGreaterThan(0);
  });

  // === Including file info ===
  test('includes file path and line number', () => {
    const content = 'line one\napi_key = "sk-real1234567890abcdefghij"\nline three';
    const findings = scanForSecrets(content, '/test/config.json');
    expect(findings[0].file).toBe('/test/config.json');
    expect(findings[0].line).toBe(2);
  });

  test('masks secret values in description', () => {
    const findings = scanForSecrets('secret = "sk-verylongsecretkeythatshouldbepartiallymasked"');
    expect(findings[0].description).not.toContain('verylongsecretkeythatshouldbepartiallymasked');
  });
});
