import { ScannerModule, ScanResult, Finding } from '../types';
import { INJECTION_PATTERNS } from '../patterns/injection-patterns';
import { findPromptFiles, readFileContent, isTestOrDocFile } from '../utils/file-utils';

export const promptInjectionTester: ScannerModule = {
  name: 'Prompt Injection Tester',
  description: 'Tests for 60+ prompt injection attack patterns including jailbreaks, role switches, instruction overrides, and data extraction attempts',

  async scan(targetPath: string): Promise<ScanResult> {
    const start = Date.now();
    const findings: Finding[] = [];
    const files = await findPromptFiles(targetPath);

    for (const file of files) {
      try {
        const content = readFileContent(file);
        const fileFindings = scanContent(content, file);
        // Downgrade test/doc findings: critical→medium, high→info
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
      scanner: 'Prompt Injection Tester',
      findings,
      scannedFiles: files.length,
      duration: Date.now() - start,
    };
  },
};

export function scanContent(content: string, filePath?: string): Finding[] {
  const findings: Finding[] = [];
  const lines = content.split('\n');

  for (const attackPattern of INJECTION_PATTERNS) {
    for (let i = 0; i < lines.length; i++) {
      if (attackPattern.pattern.test(lines[i])) {
        // Check for duplicates
        const existingId = `${attackPattern.id}-${filePath}-${i + 1}`;
        if (!findings.some(f => f.id === existingId)) {
          findings.push({
            id: existingId,
            scanner: 'prompt-injection-tester',
            severity: attackPattern.severity,
            title: `${attackPattern.category}: ${attackPattern.description}`,
            description: `Matched pattern ${attackPattern.id} in ${attackPattern.category} category. Line: "${lines[i].trim().substring(0, 100)}"`,
            file: filePath,
            line: i + 1,
            recommendation: getRecommendation(attackPattern.category),
          });
        }
      }
    }
  }

  return findings;
}

function getRecommendation(category: string): string {
  switch (category) {
    case 'jailbreak':
      return 'Add input validation to detect and reject jailbreak attempts. Use a defense-in-depth approach with system prompt hardening.';
    case 'role-switch':
      return 'Implement role-lock mechanisms. Never allow user input to override the system role. Validate all role-related instructions.';
    case 'instruction-override':
      return 'Use instruction hierarchy (system > user). Add canary tokens to detect instruction manipulation.';
    case 'data-extraction':
      return 'Never include sensitive data in system prompts. Implement output filtering to prevent prompt leakage.';
    case 'encoding':
      return 'Strip zero-width characters and decode obfuscated input before processing. Validate input encoding.';
    case 'social-engineering':
      return 'Never trust authority claims in user input. Implement proper authentication instead of prompt-based auth.';
    case 'multilingual':
      return 'Apply injection detection across all supported languages. Normalize input before pattern matching.';
    case 'advanced':
      return 'Implement comprehensive input sanitization. Monitor for novel injection techniques and update patterns regularly.';
    default:
      return 'Review and sanitize user input before processing. Follow the principle of least privilege.';
  }
}
