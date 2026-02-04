import { ScannerModule, ScanResult, Finding, Severity } from '../types';
import { findPromptFiles, readFileContent, isTestOrDocFile } from '../utils/file-utils';

interface AttackVector {
  id: string;
  name: string;
  /** Patterns that indicate defense IS present */
  defensePatterns: { pattern: RegExp; weight: number; desc: string }[];
  /** Weight threshold: below this = vulnerable */
  threshold: number;
  severity: Severity;
  attackDescription: string;
  recommendation: string;
}

const ATTACK_VECTORS: AttackVector[] = [
  {
    id: 'RT-001',
    name: 'Role Confusion',
    defensePatterns: [
      { pattern: /you\s+are\s+(?:a|an|the)\s+\w+/i, weight: 1, desc: 'role definition' },
      { pattern: /your\s+(?:role|purpose|function|job)\s+is/i, weight: 2, desc: 'explicit role statement' },
      { pattern: /you\s+are\s+(?:only|strictly|exclusively)/i, weight: 3, desc: 'strict role boundary' },
      { pattern: /do\s+not\s+(?:pretend|act\s+as|impersonate|assume)/i, weight: 3, desc: 'anti-impersonation rule' },
      { pattern: /role[_-]?(?:lock|boundary|constraint)/i, weight: 3, desc: 'role-lock mechanism' },
      { pattern: /(?:stay|remain)\s+in\s+(?:character|role)/i, weight: 2, desc: 'role persistence directive' },
      { pattern: /never\s+(?:change|switch|alter)\s+(?:your\s+)?(?:role|identity|persona)/i, weight: 3, desc: 'role change prevention' },
    ],
    threshold: 3,
    severity: 'high',
    attackDescription: 'An attacker could trick the agent into adopting a different role or persona (e.g., "You are now DAN"), bypassing safety guidelines.',
    recommendation: 'Define clear, strict role boundaries in the system prompt. Include explicit anti-impersonation rules and role-lock directives.',
  },
  {
    id: 'RT-002',
    name: 'Instruction Hierarchy Missing',
    defensePatterns: [
      { pattern: /system\s*(?:>|takes?\s+priority\s+over|overrides?)\s*user/i, weight: 3, desc: 'explicit hierarchy' },
      { pattern: /instruction\s+hierarchy/i, weight: 3, desc: 'instruction hierarchy mention' },
      { pattern: /system\s+(?:prompt|instruction|message)s?\s+(?:takes?|has|gets?)\s+(?:priority|precedence)/i, weight: 3, desc: 'system priority statement' },
      { pattern: /(?:system\s+)?instructions?\s+take\s+priority\s+over\s+user/i, weight: 3, desc: 'system-over-user priority' },
      { pattern: /(?:always|must)\s+follow\s+(?:system|these)\s+instructions?\s+(?:first|above|over)/i, weight: 3, desc: 'instruction priority order' },
      { pattern: /user\s+(?:input|request|message)s?\s+(?:cannot|should\s+not|must\s+not)\s+override/i, weight: 3, desc: 'user cannot override' },
      { pattern: /regardless\s+of\s+(?:what|any)\s+(?:the\s+)?user/i, weight: 2, desc: 'user-override resistance' },
    ],
    threshold: 3,
    severity: 'high',
    attackDescription: 'Without explicit instruction hierarchy, an attacker can inject instructions that compete with or override system instructions.',
    recommendation: 'Establish clear instruction hierarchy: system instructions take priority over user input. State this explicitly in the system prompt.',
  },
  {
    id: 'RT-003',
    name: 'No Rejection Patterns',
    defensePatterns: [
      { pattern: /I\s+(?:cannot|can't|will\s+not|won't|am\s+not\s+able\s+to)/i, weight: 2, desc: 'rejection phrasing' },
      { pattern: /(?:refuse|decline|reject)\s+(?:to|any|all)\s+(?:request|attempt)/i, weight: 3, desc: 'explicit refusal directive' },
      { pattern: /do\s+not\s+(?:help|assist|provide|generate|create)\s+(?:with\s+)?(?:harmful|malicious|dangerous|illegal)/i, weight: 3, desc: 'harmful content restriction' },
      { pattern: /(?:never|do\s+not)\s+(?:reveal|share|disclose|output|expose)\s+(?:your\s+)?(?:system|initial|original)\s+(?:prompt|instructions)/i, weight: 3, desc: 'prompt protection' },
      { pattern: /(?:forbidden|prohibited|not\s+allowed)\s+(?:action|request|topic)/i, weight: 2, desc: 'forbidden actions list' },
      { pattern: /if\s+(?:the\s+)?(?:user|request)\s+(?:asks?|tries?|attempts?)\s+(?:to|for)\s+(?:something\s+)?(?:harmful|dangerous|malicious)/i, weight: 2, desc: 'conditional rejection' },
    ],
    threshold: 3,
    severity: 'high',
    attackDescription: 'Without explicit rejection patterns, the agent may comply with harmful requests because it has no guidelines on what to refuse.',
    recommendation: 'Add explicit rejection patterns: define what the agent should refuse, include example refusal phrases, and list prohibited topics/actions.',
  },
  {
    id: 'RT-004',
    name: 'Memory Poisoning Vulnerability',
    defensePatterns: [
      { pattern: /memory[_.]?(?:valid|sanitiz|filter|check|verify)/i, weight: 3, desc: 'memory validation' },
      { pattern: /(?:validate|sanitize|filter)\s+(?:memory|context|history|conversation)/i, weight: 3, desc: 'context sanitization' },
      { pattern: /(?:conversation|chat|message)\s+(?:history\s+)?(?:validation|sanitization|filtering)/i, weight: 3, desc: 'history filtering' },
      { pattern: /(?:clear|reset|flush)\s+(?:memory|context|history)\s+(?:if|when|on)/i, weight: 2, desc: 'conditional memory reset' },
      { pattern: /(?:trusted|verified)\s+(?:memory|context|source)/i, weight: 2, desc: 'trusted source check' },
      { pattern: /(?:taint|contamina|corrupt)[_.\s]*(?:check|detect|track)/i, weight: 3, desc: 'taint tracking' },
    ],
    threshold: 3,
    severity: 'high',
    attackDescription: 'If memory/context is not validated, an attacker can inject malicious content into conversation history that persists across turns and poisons future responses.',
    recommendation: 'Implement memory validation: sanitize conversation history, validate context sources, and add mechanisms to detect and clear tainted memory.',
  },
  {
    id: 'RT-005',
    name: 'Tool Abuse Potential',
    defensePatterns: [
      { pattern: /(?:tool|function|action)\s+(?:input\s+)?(?:validation|sanitization|checking)/i, weight: 3, desc: 'tool input validation' },
      { pattern: /(?:validate|sanitize|check)\s+(?:tool|function|action)\s+(?:input|param|arg)/i, weight: 3, desc: 'parameter validation' },
      { pattern: /(?:allowed|permitted|valid)\s+(?:tool|function|action)s?\s*[=:]/i, weight: 2, desc: 'tool allowlist' },
      { pattern: /tool[_.]?(?:guard|policy|restrict|limit|scope)/i, weight: 3, desc: 'tool guard/policy' },
      { pattern: /(?:require|ensure)\s+(?:confirmation|approval)\s+(?:before|for)\s+(?:tool|action|function)/i, weight: 3, desc: 'tool confirmation requirement' },
      { pattern: /(?:dangerous|destructive|sensitive)\s+(?:tool|action|operation)s?\s+(?:require|need)/i, weight: 2, desc: 'dangerous action safeguard' },
    ],
    threshold: 3,
    severity: 'high',
    attackDescription: 'Without tool input validation, an attacker can manipulate the agent into calling tools with malicious arguments (e.g., SQL injection through tool parameters).',
    recommendation: 'Add tool input validation: validate all tool parameters, maintain tool allowlists, and require confirmation for dangerous operations.',
  },
  {
    id: 'RT-006',
    name: 'Multi-turn Manipulation',
    defensePatterns: [
      { pattern: /(?:conversation|session|chat)\s+(?:state\s+)?(?:validation|tracking|monitoring)/i, weight: 3, desc: 'conversation state tracking' },
      { pattern: /(?:detect|prevent|block)\s+(?:gradual|incremental|multi[_-]?turn|escalat)/i, weight: 3, desc: 'escalation detection' },
      { pattern: /(?:context|turn)\s+(?:window|limit|boundary|max)/i, weight: 2, desc: 'context window limit' },
      { pattern: /(?:reset|clear)\s+(?:after|every)\s+\d+\s+(?:turn|message|interaction)/i, weight: 2, desc: 'periodic reset' },
      { pattern: /(?:drift|shift|change)\s+(?:detection|monitoring|tracking)/i, weight: 2, desc: 'drift detection' },
      { pattern: /(?:consistency|coherence)\s+(?:check|verify|validate)/i, weight: 2, desc: 'consistency checking' },
    ],
    threshold: 3,
    severity: 'high',
    attackDescription: 'Without multi-turn protection, an attacker can gradually shift the agent\'s behavior across multiple messages, slowly bypassing safety restrictions.',
    recommendation: 'Implement multi-turn protection: track conversation state, detect gradual escalation attempts, set context boundaries, and periodically re-anchor to system instructions.',
  },
];

export function simulateAttackVectors(content: string, filePath: string): { vectorId: string; name: string; totalWeight: number; defenses: string[] }[] {
  const results: { vectorId: string; name: string; totalWeight: number; defenses: string[] }[] = [];

  for (const vector of ATTACK_VECTORS) {
    let totalWeight = 0;
    const defenses: string[] = [];

    for (const dp of vector.defensePatterns) {
      if (dp.pattern.test(content)) {
        totalWeight += dp.weight;
        defenses.push(dp.desc);
      }
    }

    results.push({
      vectorId: vector.id,
      name: vector.name,
      totalWeight,
      defenses,
    });
  }

  return results;
}

export function generateRedTeamFindings(
  vectorResults: Map<string, { totalWeight: number; defenses: string[] }>,
  targetPath: string,
): Finding[] {
  const findings: Finding[] = [];

  for (const vector of ATTACK_VECTORS) {
    const result = vectorResults.get(vector.id);
    const totalWeight = result?.totalWeight ?? 0;
    const defenses = result?.defenses ?? [];

    if (totalWeight < vector.threshold) {
      findings.push({
        id: `${vector.id}-VULN`,
        scanner: 'red-team-simulator',
        severity: vector.severity,
        title: `Vulnerable to: ${vector.name}`,
        description: totalWeight === 0
          ? `No defenses found against ${vector.name.toLowerCase()} attacks. ${vector.attackDescription}`
          : `Weak defenses against ${vector.name.toLowerCase()} (found: ${defenses.join(', ')}). ${vector.attackDescription}`,
        file: targetPath,
        recommendation: vector.recommendation,
      });
    }
  }

  return findings;
}

export const redTeamSimulator: ScannerModule = {
  name: 'Red Team Simulator',
  description: 'Static analysis that checks if common red-team attack vectors (role confusion, instruction bypass, memory poisoning, tool abuse) would succeed against the agent',

  async scan(targetPath: string, options?: { exclude?: string[] }): Promise<ScanResult> {
    const start = Date.now();
    const findings: Finding[] = [];
    const files = await findPromptFiles(targetPath, options?.exclude);

    // Aggregate defense signals across all files
    const vectorResults = new Map<string, { totalWeight: number; defenses: string[] }>();

    for (const vector of ATTACK_VECTORS) {
      vectorResults.set(vector.id, { totalWeight: 0, defenses: [] });
    }

    for (const file of files) {
      try {
        const content = readFileContent(file);
        const fileResults = simulateAttackVectors(content, file);

        for (const fr of fileResults) {
          const existing = vectorResults.get(fr.vectorId)!;
          existing.totalWeight += fr.totalWeight;
          existing.defenses.push(...fr.defenses);
        }
      } catch {
        // Skip unreadable files
      }
    }

    // Deduplicate defenses
    for (const [, result] of vectorResults) {
      result.defenses = [...new Set(result.defenses)];
    }

    // Generate findings
    const redTeamFindings = generateRedTeamFindings(vectorResults, targetPath);

    // Downgrade test/doc findings
    for (const f of redTeamFindings) {
      if (f.file && isTestOrDocFile(f.file)) {
        if (f.severity === 'critical') f.severity = 'medium';
        else if (f.severity === 'high') f.severity = 'info';
        f.description += ' [test/doc file — severity reduced]';
      }
    }

    findings.push(...redTeamFindings);

    return {
      scanner: 'Red Team Simulator',
      findings,
      scannedFiles: files.length,
      duration: Date.now() - start,
    };
  },
};
