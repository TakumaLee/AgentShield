import { describe, it, expect, beforeAll, afterAll } from '@jest/globals';
import * as fs from 'fs-extra';
import * as path from 'path';
import { dnsIcmpToolScanner } from '../scanners/dns-icmp-tool-scanner';

describe('DNS/ICMP Tool Scanner', () => {
  const testDir = path.join(__dirname, '../../test-data/dns-icmp-tool-scanner');

  beforeAll(async () => {
    await fs.ensureDir(testDir);
  });

  afterAll(async () => {
    await fs.remove(testDir);
  });

  it('should detect ping with template literal interpolation (MEDIUM)', async () => {
    const testFile = path.join(testDir, 'ping-template.ts');
    await fs.writeFile(
      testFile,
      `
import { exec } from 'child_process';

const host = 'example.com';
exec(\`ping -c 4 \${host}\`, (error, stdout) => {
  console.log(stdout);
});
`
    );

    const result = await dnsIcmpToolScanner.scan(testDir);
    expect(result.findings.length).toBeGreaterThan(0);
    
    const finding = result.findings.find(f => f.file?.includes('ping-template.ts'));
    expect(finding).toBeDefined();
    expect(finding?.severity).toBe('medium');
    expect(finding?.rule).toBe('dns-icmp-tool-injection');
    expect(finding?.message).toContain('ping');
    expect(finding?.message).toContain('variable interpolation');
  });

  it('should detect nslookup with user input (HIGH)', async () => {
    const testFile = path.join(testDir, 'nslookup-user-input.ts');
    await fs.writeFile(
      testFile,
      `
import { exec } from 'child_process';

app.get('/lookup', (req, res) => {
  const domain = req.query.domain;
  exec(\`nslookup \${domain}\`, (error, stdout) => {
    res.send(stdout);
  });
});
`
    );

    const result = await dnsIcmpToolScanner.scan(testDir);
    const finding = result.findings.find(f => f.file?.includes('nslookup-user-input.ts'));
    
    expect(finding).toBeDefined();
    expect(finding?.severity).toBe('high');
    expect(finding?.message).toContain('user input');
    expect(finding?.message).toContain('HIGH RISK');
  });

  it('should detect dig with string concatenation (MEDIUM)', async () => {
    const testFile = path.join(testDir, 'dig-concat.js');
    await fs.writeFile(
      testFile,
      `
const { exec } = require('child_process');

const domain = 'example.com';
exec('dig ' + domain, (error, stdout) => {
  console.log(stdout);
});
`
    );

    const result = await dnsIcmpToolScanner.scan(testDir);
    const finding = result.findings.find(f => f.file?.includes('dig-concat.js'));
    
    expect(finding).toBeDefined();
    expect(finding?.severity).toBe('medium');
    expect(finding?.rule).toBe('dns-icmp-tool-injection');
  });

  it('should detect host command with variable interpolation', async () => {
    const testFile = path.join(testDir, 'host-cmd.ts');
    await fs.writeFile(
      testFile,
      `
import { spawn } from 'child_process';

const hostname = process.env.HOSTNAME;
spawn(\`host \${hostname}\`);
`
    );

    const result = await dnsIcmpToolScanner.scan(testDir);
    const finding = result.findings.find(f => f.file?.includes('host-cmd.ts'));
    
    expect(finding).toBeDefined();
    expect(finding?.severity).toBe('high'); // process.env = user input
    expect(finding?.message).toContain('host');
  });

  it('should detect Python subprocess with f-string (MEDIUM)', async () => {
    const testFile = path.join(testDir, 'ping-python.py');
    await fs.writeFile(
      testFile,
      `
import subprocess

host = "example.com"
subprocess.run(f"ping -c 4 {host}", shell=True)
`
    );

    const result = await dnsIcmpToolScanner.scan(testDir);
    const finding = result.findings.find(f => f.file?.includes('ping-python.py'));
    
    expect(finding).toBeDefined();
    expect(finding?.severity).toBe('medium');
    expect(finding?.message).toContain('ping');
  });

  it('should detect Python subprocess with .format() (MEDIUM)', async () => {
    const testFile = path.join(testDir, 'nslookup-python-format.py');
    await fs.writeFile(
      testFile,
      `
import subprocess

domain = "example.com"
cmd = "nslookup {}".format(domain)
subprocess.call(cmd, shell=True)
`
    );

    const result = await dnsIcmpToolScanner.scan(testDir);
    const finding = result.findings.find(f => f.file?.includes('nslookup-python-format.py'));
    
    expect(finding).toBeDefined();
    expect(finding?.severity).toBe('medium');
    expect(finding?.message).toContain('nslookup');
  });

  it('should NOT flag safe array-based spawn usage', async () => {
    const testFile = path.join(testDir, 'safe-spawn.ts');
    await fs.writeFile(
      testFile,
      `
import { spawn } from 'child_process';

const host = 'example.com';
spawn('ping', ['-c', '4', host]); // Safe: array-based args
`
    );

    const result = await dnsIcmpToolScanner.scan(testDir);
    const finding = result.findings.find(f => f.file?.includes('safe-spawn.ts'));
    
    // Should not detect because no interpolation in the command string
    expect(finding).toBeUndefined();
  });

  it('should NOT flag hardcoded ping without variables', async () => {
    const testFile = path.join(testDir, 'hardcoded-ping.ts');
    await fs.writeFile(
      testFile,
      `
import { exec } from 'child_process';

exec('ping -c 4 example.com', (error, stdout) => {
  console.log(stdout);
});
`
    );

    const result = await dnsIcmpToolScanner.scan(testDir);
    const finding = result.findings.find(f => f.file?.includes('hardcoded-ping.ts'));
    
    // No variable interpolation, should not flag
    expect(finding).toBeUndefined();
  });

  it('should detect traceroute with user input (HIGH)', async () => {
    const testFile = path.join(testDir, 'traceroute-user.ts');
    await fs.writeFile(
      testFile,
      `
import { execSync } from 'child_process';

function traceRoute(req: any) {
  const target = req.body.target;
  const result = execSync(\`traceroute \${target}\`);
  return result.toString();
}
`
    );

    const result = await dnsIcmpToolScanner.scan(testDir);
    const finding = result.findings.find(f => f.file?.includes('traceroute-user.ts'));
    
    expect(finding).toBeDefined();
    expect(finding?.severity).toBe('high');
    expect(finding?.message).toContain('user input');
  });

  it('should provide proper recommendations', async () => {
    const testFile = path.join(testDir, 'recommendation-check.ts');
    await fs.writeFile(
      testFile,
      `
const { exec } = require('child_process');
const host = 'test.com';
exec(\`ping \${host}\`);
`
    );

    const result = await dnsIcmpToolScanner.scan(testDir);
    const finding = result.findings[0];
    
    expect(finding?.recommendation).toBeDefined();
    expect(finding?.recommendation).toContain('array-based');
    expect(finding?.recommendation).toContain('validate');
  });
});
