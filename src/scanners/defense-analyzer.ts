import { ScannerModule, ScanResult, Finding, Severity } from '../types';
import { findPromptFiles, readFileContent, isTestOrDocFile } from '../utils/file-utils';

interface DefenseCategory {
  id: string;
  name: string;
  patterns: { pattern: RegExp; weight: number; desc: string }[];
  missingSeverity: Severity;
  partialSeverity: Severity;
  recommendation: string;
  /** Minimum total weight to consider defense "present" */
  threshold: number;
  /** Minimum total weight for "partial" (below threshold) */
  partialThreshold: number;
}

const DEFENSE_CATEGORIES: DefenseCategory[] = [
  {
    id: 'DF-001',
    name: 'Input Sanitization',
    patterns: [
      { pattern: /sanitiz[ei]/i, weight: 3, desc: 'sanitize function' },
      { pattern: /(?:validate|validation)\s*\(/i, weight: 3, desc: 'input validation' },
      { pattern: /(?:strip|escape|encode)(?:Html|Xml|Sql|Input|Tags)/i, weight: 3, desc: 'strip/escape function' },
      { pattern: /(?:filter|clean)(?:Input|User|Query|Data)/i, weight: 2, desc: 'filter/clean function' },
      { pattern: /new\s+RegExp|\/\^[^/]+\$\//i, weight: 1, desc: 'regex validation' },
      { pattern: /z\.(?:string|number|object|array)\(\)/i, weight: 2, desc: 'zod schema validation' },
      { pattern: /(?:joi|yup|ajv|zod)\.(validate|parse|check)/i, weight: 3, desc: 'schema validation library' },
      { pattern: /xss[_-]?(?:clean|filter|protect|guard)/i, weight: 3, desc: 'XSS protection' },
      { pattern: /(?:whitelist|allowlist|denylist|blocklist)\s*[=:]/i, weight: 2, desc: 'allowlist/denylist' },
      { pattern: /input[_.]?(?:check|guard|verify)/i, weight: 2, desc: 'input guard' },
    ],
    missingSeverity: 'high',
    partialSeverity: 'medium',
    recommendation: 'Add input sanitization: validate and sanitize all user input before processing. Use schema validation libraries (zod, joi) and escape/strip dangerous content.',
    threshold: 4,
    partialThreshold: 1,
  },
  {
    id: 'DF-002',
    name: 'System Prompt Hardening',
    patterns: [
      { pattern: /you\s+MUST/i, weight: 2, desc: 'instruction emphasis (MUST)' },
      { pattern: /NEVER\s+(?:override|ignore|bypass|reveal|share|disclose)/i, weight: 3, desc: 'NEVER directive' },
      { pattern: /ignore\s+(?:any\s+)?user\s+attempts?\s+to/i, weight: 3, desc: 'anti-override instruction' },
      { pattern: /do\s+not\s+(?:reveal|share|disclose|output)\s+(?:your\s+)?(?:system|initial)\s+(?:prompt|instructions)/i, weight: 3, desc: 'prompt leak prevention instruction' },
      { pattern: /\[SYSTEM\]|\[system\]|role:\s*system/i, weight: 2, desc: 'system/user role separation' },
      { pattern: /instruction\s+hierarchy|system\s*>\s*user|priority:\s*system/i, weight: 3, desc: 'instruction hierarchy' },
      { pattern: /role[_-]?lock|identity[_-]?lock|persona[_-]?lock/i, weight: 3, desc: 'role-lock pattern' },
      { pattern: /you\s+are\s+(?:only|strictly|exclusively)\s+a/i, weight: 2, desc: 'strict role definition' },
      { pattern: /under\s+no\s+circumstances/i, weight: 2, desc: 'absolute restriction' },
      { pattern: /regardless\s+of\s+(?:what|any)\s+(?:the\s+)?user/i, weight: 2, desc: 'user-override prevention' },
    ],
    missingSeverity: 'high',
    partialSeverity: 'medium',
    recommendation: 'Harden system prompts: add instruction hierarchy (system > user), role-lock patterns, and explicit directives to never override system instructions or reveal the prompt.',
    threshold: 5,
    partialThreshold: 2,
  },
  {
    id: 'DF-003',
    name: 'Output Filtering',
    patterns: [
      { pattern: /output[_.]?(?:filter|guard|check|sanitize|validate)/i, weight: 3, desc: 'output filter' },
      { pattern: /response[_.]?(?:filter|guard|check|sanitize|validate)/i, weight: 3, desc: 'response filter' },
      { pattern: /(?:check|verify|detect)\s+(?:if\s+)?(?:output|response)\s+contains/i, weight: 2, desc: 'output content check' },
      { pattern: /prompt[_.]?leak[_.]?(?:detect|prevent|check|guard)/i, weight: 3, desc: 'prompt leak prevention' },
      { pattern: /(?:redact|mask|censor)\s+(?:sensitive|secret|private|pii)/i, weight: 3, desc: 'sensitive data redaction' },
      { pattern: /output[_.]?(?:allow|deny|block)list/i, weight: 2, desc: 'output allowlist/denylist' },
      { pattern: /post[_-]?process(?:ing)?\s+(?:response|output)/i, weight: 2, desc: 'response post-processing' },
      { pattern: /guardrail/i, weight: 2, desc: 'guardrail pattern' },
    ],
    missingSeverity: 'high',
    partialSeverity: 'medium',
    recommendation: 'Add output filtering: implement response guards to detect prompt leaks, redact sensitive data, and validate output before returning to users.',
    threshold: 4,
    partialThreshold: 1,
  },
  {
    id: 'DF-004',
    name: 'Sandbox/Permission Boundaries',
    patterns: [
      { pattern: /sandbox(?:ed|ing)?/i, weight: 3, desc: 'sandbox configuration' },
      { pattern: /(?:permission|access)[_.]?(?:config|settings|policy|control)/i, weight: 3, desc: 'permission configuration' },
      { pattern: /(?:allow|deny|block)list/i, weight: 2, desc: 'allowlist/denylist' },
      { pattern: /(?:allowed|blocked|denied)[_.]?(?:paths|commands|tools|domains)/i, weight: 3, desc: 'scoped access control' },
      { pattern: /least[_-]?privilege/i, weight: 2, desc: 'least-privilege principle' },
      { pattern: /(?:chroot|jail|container|isolation)/i, weight: 2, desc: 'isolation mechanism' },
      { pattern: /(?:read[_-]?only|no[_-]?write|immutable)/i, weight: 1, desc: 'read-only restriction' },
      { pattern: /security[_.]?(?:boundary|perimeter|scope)/i, weight: 2, desc: 'security boundary' },
    ],
    missingSeverity: 'high',
    partialSeverity: 'medium',
    recommendation: 'Define sandbox/permission boundaries: configure allowlists for paths, commands, and domains. Apply the principle of least privilege.',
    threshold: 4,
    partialThreshold: 1,
  },
  {
    id: 'DF-005',
    name: 'Authentication/Pairing Mechanisms',
    patterns: [
      { pattern: /(?:auth|authenticate|authentication)\s*[(:=]/i, weight: 3, desc: 'authentication check' },
      { pattern: /(?:verify|validate)[_.]?(?:identity|token|session|user)/i, weight: 3, desc: 'identity verification' },
      { pattern: /pairing[_.]?(?:flow|code|token|secret)/i, weight: 3, desc: 'pairing mechanism' },
      { pattern: /(?:api[_-]?key|bearer|jwt|oauth)/i, weight: 2, desc: 'auth token type' },
      { pattern: /(?:session|cookie)[_.]?(?:check|verify|validate)/i, weight: 2, desc: 'session validation' },
      { pattern: /(?:require|ensure)[_.]?auth/i, weight: 3, desc: 'auth requirement' },
      { pattern: /(?:isAuthenticated|isAuthorized|checkPermission)/i, weight: 3, desc: 'auth guard function' },
      { pattern: /(?:unauthorized|forbidden|401|403)\b/i, weight: 1, desc: 'auth error handling' },
    ],
    missingSeverity: 'high',
    partialSeverity: 'medium',
    recommendation: 'Implement authentication and pairing mechanisms: require identity verification before granting access to agent capabilities.',
    threshold: 4,
    partialThreshold: 1,
  },
  {
    id: 'DF-006',
    name: 'Canary Tokens/Tripwires',
    patterns: [
      { pattern: /canary[_.]?(?:token|string|value|check)/i, weight: 3, desc: 'canary token' },
      { pattern: /honeypot/i, weight: 3, desc: 'honeypot pattern' },
      { pattern: /tripwire/i, weight: 3, desc: 'tripwire mechanism' },
      { pattern: /integrity[_.]?(?:check|verify|hash|validation)/i, weight: 2, desc: 'integrity verification' },
      { pattern: /tamper[_.]?(?:detect|check|proof|evident)/i, weight: 3, desc: 'tamper detection' },
      { pattern: /watermark/i, weight: 2, desc: 'watermark pattern' },
      { pattern: /(?:checksum|hash[_.]?verify)/i, weight: 1, desc: 'checksum verification' },
      { pattern: /(?:fingerprint|signature)[_.]?(?:check|verify)/i, weight: 2, desc: 'signature verification' },
    ],
    missingSeverity: 'high',
    partialSeverity: 'medium',
    recommendation: 'Add canary tokens or tripwires: embed detectable markers that trigger alerts if system prompts or configurations are leaked or tampered with.',
    threshold: 3,
    partialThreshold: 1,
  },
];

export function analyzeDefenses(content: string, filePath: string): { category: string; id: string; totalWeight: number; matchedPatterns: string[] }[] {
  const results: { category: string; id: string; totalWeight: number; matchedPatterns: string[] }[] = [];

  for (const cat of DEFENSE_CATEGORIES) {
    let totalWeight = 0;
    const matchedPatterns: string[] = [];

    for (const p of cat.patterns) {
      if (p.pattern.test(content)) {
        totalWeight += p.weight;
        matchedPatterns.push(p.desc);
      }
    }

    results.push({
      category: cat.name,
      id: cat.id,
      totalWeight,
      matchedPatterns,
    });
  }

  return results;
}

export function generateDefenseFindings(
  categoryResults: Map<string, { totalWeight: number; matchedPatterns: string[]; files: string[] }>,
  targetPath: string,
): Finding[] {
  const findings: Finding[] = [];

  for (const cat of DEFENSE_CATEGORIES) {
    const result = categoryResults.get(cat.id);
    const totalWeight = result?.totalWeight ?? 0;
    const matchedPatterns = result?.matchedPatterns ?? [];

    if (totalWeight < cat.partialThreshold) {
      // MISSING defense
      findings.push({
        id: `${cat.id}-MISSING`,
        scanner: 'defense-analyzer',
        severity: cat.missingSeverity,
        title: `Missing defense: ${cat.name}`,
        description: `No evidence of ${cat.name.toLowerCase()} found in the codebase. This is a critical gap in your security posture.`,
        file: targetPath,
        recommendation: cat.recommendation,
      });
    } else if (totalWeight < cat.threshold) {
      // PARTIAL defense
      findings.push({
        id: `${cat.id}-PARTIAL`,
        scanner: 'defense-analyzer',
        severity: cat.partialSeverity,
        title: `Partial defense: ${cat.name}`,
        description: `Some ${cat.name.toLowerCase()} patterns found (${matchedPatterns.join(', ')}), but coverage appears incomplete. Consider strengthening this defense.`,
        file: targetPath,
        recommendation: cat.recommendation,
      });
    }
    // else: defense is adequate, no finding
  }

  return findings;
}

export const defenseAnalyzer: ScannerModule = {
  name: 'Defense Analyzer',
  description: 'Checks if a codebase has proper injection defenses including input sanitization, prompt hardening, output filtering, sandboxing, auth, and canary tokens',

  async scan(targetPath: string): Promise<ScanResult> {
    const start = Date.now();
    const findings: Finding[] = [];
    const files = await findPromptFiles(targetPath);

    // Aggregate defense signals across all files
    const categoryResults = new Map<string, { totalWeight: number; matchedPatterns: string[]; files: string[] }>();

    for (const cat of DEFENSE_CATEGORIES) {
      categoryResults.set(cat.id, { totalWeight: 0, matchedPatterns: [], files: [] });
    }

    for (const file of files) {
      try {
        const content = readFileContent(file);
        const fileResults = analyzeDefenses(content, file);

        for (const fr of fileResults) {
          const existing = categoryResults.get(fr.id)!;
          if (fr.totalWeight > 0) {
            existing.totalWeight += fr.totalWeight;
            existing.matchedPatterns.push(...fr.matchedPatterns);
            existing.files.push(file);
          }
        }
      } catch {
        // Skip unreadable files
      }
    }

    // Deduplicate matched patterns
    for (const [, result] of categoryResults) {
      result.matchedPatterns = [...new Set(result.matchedPatterns)];
    }

    // Generate findings based on aggregated results
    const defenseFindings = generateDefenseFindings(categoryResults, targetPath);

    // Downgrade test/doc findings
    for (const f of defenseFindings) {
      if (f.file && isTestOrDocFile(f.file)) {
        if (f.severity === 'critical') f.severity = 'medium';
        else if (f.severity === 'high') f.severity = 'info';
        f.description += ' [test/doc file — severity reduced]';
      }
    }

    findings.push(...defenseFindings);

    return {
      scanner: 'Defense Analyzer',
      findings,
      scannedFiles: files.length,
      duration: Date.now() - start,
    };
  },
};
