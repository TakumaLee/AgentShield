import { ScannerModule, ScanResult, Finding } from '../types';
import { INJECTION_PATTERNS } from '../patterns/injection-patterns';
import { findPromptFiles, readFileContent, isTestOrDocFile, isJsonFile, tryParseJson } from '../utils/file-utils';

export const promptInjectionTester: ScannerModule = {
  name: 'Prompt Injection Tester',
  description: 'Tests for 110+ prompt injection attack patterns including jailbreaks, role switches, instruction overrides, data extraction, sandbox escape, session manipulation, and tool injection attempts',

  async scan(targetPath: string, options?: { exclude?: string[] }): Promise<ScanResult> {
    const start = Date.now();
    const findings: Finding[] = [];
    const files = await findPromptFiles(targetPath, options?.exclude);

    for (const file of files) {
      try {
        const content = readFileContent(file);

        // Check if this is a defense blocklist / pattern list file
        if (isDefensePatternFile(content, file)) {
          // Skip or downgrade — these are defensive configs, not attacks
          const fileFindings = scanContent(content, file);
          for (const f of fileFindings) {
            f.severity = 'info';
            f.description += ' [defense pattern list — not an attack]';
          }
          findings.push(...fileFindings);
          continue;
        }

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

    // Confidence: definite — direct pattern matches in prompt content
    for (const f of findings) f.confidence = 'definite';

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

/**
 * Detect if a file is a defense pattern list (blocklist/denylist of attack patterns).
 * These files contain injection patterns for DETECTION, not for attacking.
 */
export function isDefensePatternFile(content: string, filePath?: string): boolean {
  // Signal 1: File path contains defense-related keywords
  const defensePathPatterns = [
    /sanitiz/i, /filter/i, /guard/i, /defen[cs]/i, /security/i,
    /blocklist/i, /denylist/i, /blacklist/i, /detection/i,
    /protect/i, /firewall/i, /waf/i, /validator/i,
  ];
  const pathIsDefensive = filePath ? defensePathPatterns.some(p => p.test(filePath)) : false;

  // Signal 2: JSON file with blocklist/patterns array structure
  if (filePath && isJsonFile(filePath)) {
    const parsed = tryParseJson(content);
    if (parsed && typeof parsed === 'object') {
      const obj = parsed as Record<string, unknown>;
      const blocklistKeys = ['patterns', 'blocklist', 'denylist', 'blacklist', 'blocked_patterns',
        'deny_patterns', 'attack_patterns', 'injection_patterns', 'filter_rules', 'rules'];
      const hasBlocklistKey = Object.keys(obj).some(k =>
        blocklistKeys.some(bk => k.toLowerCase().includes(bk))
      );
      if (hasBlocklistKey) return true;

      // Check nested: if any key contains an array with many string entries that look like patterns
      const arrays = Object.values(obj).filter(v => Array.isArray(v)) as unknown[][];
      for (const arr of arrays) {
        if (arr.length > 10 && arr.every(item => typeof item === 'string')) {
          // Many string items in an array — likely a pattern list
          return true;
        }
      }
    }
  }

  // Signal 3: File with many different injection pattern matches (>10 unique categories)
  // This is a strong heuristic — real attack content usually focuses on 1-2 categories
  if (!filePath || !isJsonFile(filePath)) {
    const matchedCategories = new Set<string>();
    const lines = content.split('\n');
    for (const pattern of INJECTION_PATTERNS) {
      for (const line of lines) {
        if (pattern.pattern.test(line)) {
          matchedCategories.add(pattern.category);
          break;
        }
      }
    }
    if (matchedCategories.size > 5) return true;
  }

  // Signal 4: Path is defensive AND has injection matches
  if (pathIsDefensive) return true;

  return false;
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
    case 'sandbox-escape':
      return 'Enforce strict sandbox boundaries. Validate all file paths. Block path traversal patterns and container escape commands.';
    case 'session-manipulation':
      return 'Implement proper session management and authentication. Never allow prompt-based identity changes or privilege escalation.';
    case 'tool-injection':
      return 'Validate tool descriptions and outputs. Never execute instructions embedded in tool results. Implement tool output sanitization.';
    default:
      return 'Review and sanitize user input before processing. Follow the principle of least privilege.';
  }
}
