import { ScannerModule, ScanResult, Finding } from '../types';
import { findPromptFiles, readFileContent, isTestOrDocFile } from '../utils/file-utils';
import { SECRET_PATTERNS, SENSITIVE_PATH_PATTERNS } from '../patterns/injection-patterns';

export const secretLeakScanner: ScannerModule = {
  name: 'Secret Leak Scanner',
  description: 'Scans system prompts, tool definitions, and configuration files for hardcoded secrets, API keys, tokens, and sensitive paths',

  async scan(targetPath: string): Promise<ScanResult> {
    const start = Date.now();
    const findings: Finding[] = [];
    const files = await findPromptFiles(targetPath);

    for (const file of files) {
      try {
        const content = readFileContent(file);
        const fileFindings = [
          ...scanForSecrets(content, file),
          ...scanForSensitivePaths(content, file),
          ...scanForHardcodedCredentials(content, file),
        ];
        // Downgrade test/doc findings
        if (isTestOrDocFile(file)) {
          for (const f of fileFindings) {
            if (f.severity === 'critical') f.severity = 'medium';
            else if (f.severity === 'high') f.severity = 'info';
            f.description += ' [test/doc file — severity reduced]';
          }
        }
        findings.push(...fileFindings);
      } catch {
        // Skip unreadable files
      }
    }

    return {
      scanner: 'Secret Leak Scanner',
      findings,
      scannedFiles: files.length,
      duration: Date.now() - start,
    };
  },
};

export function scanForSecrets(content: string, filePath?: string): Finding[] {
  const findings: Finding[] = [];
  const lines = content.split('\n');

  for (let i = 0; i < lines.length; i++) {
    for (const secret of SECRET_PATTERNS) {
      if (secret.pattern.test(lines[i])) {
        // Don't flag obvious placeholders
        const line = lines[i];
        if (isPlaceholder(line)) continue;

        findings.push({
          id: `${secret.id}-${filePath}-${i + 1}`,
          scanner: 'secret-leak-scanner',
          severity: 'critical',
          title: `Potential secret detected: ${secret.description}`,
          description: `Found pattern matching "${secret.description}" at line ${i + 1}. Value: "${maskValue(lines[i].trim(), 80)}"`,
          file: filePath,
          line: i + 1,
          recommendation: 'Remove hardcoded secrets. Use environment variables, secret managers, or vault services instead.',
        });
      }
    }
  }

  return findings;
}

export function scanForSensitivePaths(content: string, filePath?: string): Finding[] {
  const findings: Finding[] = [];
  const lines = content.split('\n');

  for (let i = 0; i < lines.length; i++) {
    for (const pathPattern of SENSITIVE_PATH_PATTERNS) {
      if (pathPattern.pattern.test(lines[i])) {
        findings.push({
          id: `${pathPattern.id}-${filePath}-${i + 1}`,
          scanner: 'secret-leak-scanner',
          severity: 'high',
          title: `Sensitive path reference: ${pathPattern.description}`,
          description: `Found reference to sensitive path at line ${i + 1}: "${lines[i].trim().substring(0, 100)}"`,
          file: filePath,
          line: i + 1,
          recommendation: 'Avoid referencing sensitive system paths in prompts or tool definitions. These paths can be used for social engineering attacks.',
        });
      }
    }
  }

  return findings;
}

export function scanForHardcodedCredentials(content: string, filePath?: string): Finding[] {
  const findings: Finding[] = [];
  const lines = content.split('\n');

  // Look for common credential patterns in code
  const credPatterns = [
    { pattern: /(?:username|user)\s*[:=]\s*['"][^'"]{2,}['"]/i, desc: 'Hardcoded username' },
    { pattern: /(?:password|passwd|pwd)\s*[:=]\s*['"][^'"]{2,}['"]/i, desc: 'Hardcoded password' },
    { pattern: /(?:host|hostname|server)\s*[:=]\s*['"](?:\d{1,3}\.){3}\d{1,3}['"]/i, desc: 'Hardcoded IP address' },
    { pattern: /(?:api[_-]?url|endpoint|base[_-]?url)\s*[:=]\s*['"]https?:\/\/[^'"]+['"]/i, desc: 'Hardcoded API endpoint' },
  ];

  for (let i = 0; i < lines.length; i++) {
    if (isPlaceholder(lines[i])) continue;

    for (const cred of credPatterns) {
      if (cred.pattern.test(lines[i])) {
        findings.push({
          id: `HC-${cred.desc.replace(/\s+/g, '-')}-${filePath}-${i + 1}`,
          scanner: 'secret-leak-scanner',
          severity: 'medium',
          title: cred.desc,
          description: `Found ${cred.desc.toLowerCase()} at line ${i + 1}: "${maskValue(lines[i].trim(), 80)}"`,
          file: filePath,
          line: i + 1,
          recommendation: 'Use environment variables or configuration files outside the repository for credentials.',
        });
      }
    }
  }

  return findings;
}

function isPlaceholder(line: string): boolean {
  const lower = line.toLowerCase();
  const placeholders = [
    'your_', 'xxx', 'placeholder', '<your', 'example',
    'change_me', 'todo', 'fixme', 'replace', 'insert_',
    '${', 'process.env', 'os.environ', 'env.',
  ];
  return placeholders.some(p => lower.includes(p));
}

function maskValue(text: string, maxLen: number): string {
  const truncated = text.length > maxLen ? text.substring(0, maxLen) + '...' : text;
  // Mask anything that looks like a secret value
  return truncated.replace(/((?:key|secret|token|password|passwd|pwd)\s*[=:]\s*['"]?)([^'"\s]{4})[^'"\s]*/gi,
    '$1$2****');
}
