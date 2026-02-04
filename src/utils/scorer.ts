import { ReportSummary, ScanResult, Severity, Confidence, Finding } from '../types';

// Diminishing returns: first findings of each severity hurt more,
// but additional ones have less impact (logarithmic scaling)
const SEVERITY_BASE_PENALTY: Record<Severity, number> = {
  critical: 20,  // Phase 1: raised from 15
  high: 5,
  medium: 1.5,
  info: 0,
};

// Cap per severity so one category can't tank the entire score
const SEVERITY_MAX_PENALTY: Record<Severity, number> = {
  critical: 50,  // Phase 1: raised from 40
  high: 30,
  medium: 15,
  info: 0,
};

// Confidence weighting: lower confidence = less penalty contribution
const CONFIDENCE_WEIGHT: Record<Confidence, number> = {
  definite: 1.0,
  likely: 0.8,
  possible: 0.6,
};

// Scanner → dimension mapping
const DIMENSION_MAP: Record<string, 'codeSafety' | 'configSafety' | 'defenseScore'> = {
  'Secret Leak Scanner': 'codeSafety',
  'Prompt Injection Tester': 'codeSafety',
  'Skill Auditor': 'codeSafety',
  'MCP Config Auditor': 'configSafety',
  'Permission Analyzer': 'configSafety',
  'Channel Surface Auditor': 'configSafety',
  'Defense Analyzer': 'defenseScore',
  'Red Team Simulator': 'defenseScore',
};

function diminishingPenalty(count: number, basePenalty: number, maxPenalty: number): number {
  if (count === 0) return 0;
  // log curve: rapid initial penalty, diminishing returns
  const raw = basePenalty * Math.log2(count + 1);
  return Math.min(raw, maxPenalty);
}

/**
 * Interaction penalty when critical AND high findings coexist.
 * Represents compounding risk from multiple severe issue types.
 */
export function interactionPenalty(critical: number, high: number): number {
  if (critical > 0 && high > 0) {
    return Math.min(5 * Math.log2(Math.min(critical, high) + 1), 10);
  }
  return 0;
}

/**
 * Calculate effective severity counts weighted by confidence.
 * E.g., 3 possible high findings = 3 × 0.6 = 1.8 effective highs.
 */
function weightedSeverityCounts(findings: Finding[]): Record<Severity, number> {
  const counts: Record<Severity, number> = { critical: 0, high: 0, medium: 0, info: 0 };

  for (const f of findings) {
    const weight = CONFIDENCE_WEIGHT[f.confidence ?? 'definite'];
    counts[f.severity] += weight;
  }

  return counts;
}

/**
 * Calculate penalty from weighted severity counts.
 */
function calculatePenaltyFromCounts(counts: Record<Severity, number>): number {
  return (
    diminishingPenalty(counts.critical, SEVERITY_BASE_PENALTY.critical, SEVERITY_MAX_PENALTY.critical) +
    diminishingPenalty(counts.high, SEVERITY_BASE_PENALTY.high, SEVERITY_MAX_PENALTY.high) +
    diminishingPenalty(counts.medium, SEVERITY_BASE_PENALTY.medium, SEVERITY_MAX_PENALTY.medium)
  );
}

/**
 * Calculate score from findings (with confidence weighting + interaction penalty).
 */
function calculateScoreFromFindings(findings: Finding[]): number {
  const counts = weightedSeverityCounts(findings);
  const penalty = calculatePenaltyFromCounts(counts) + interactionPenalty(counts.critical, counts.high);
  return Math.max(0, Math.min(100, Math.round(100 - penalty)));
}

export function calculateSummary(results: ScanResult[]): ReportSummary {
  let critical = 0;
  let high = 0;
  let medium = 0;
  let info = 0;
  let scannedFiles = 0;
  let duration = 0;

  const allFindings: Finding[] = [];
  const dimensionFindings: Record<'codeSafety' | 'configSafety' | 'defenseScore', Finding[]> = {
    codeSafety: [],
    configSafety: [],
    defenseScore: [],
  };
  const scannerBreakdown: Record<string, Record<Severity, number>> = {};

  for (const result of results) {
    scannedFiles += result.scannedFiles;
    duration += result.duration;

    // Initialize scanner breakdown
    if (!scannerBreakdown[result.scanner]) {
      scannerBreakdown[result.scanner] = { critical: 0, high: 0, medium: 0, info: 0 };
    }

    for (const finding of result.findings) {
      // Raw severity counts (unweighted, for display)
      switch (finding.severity) {
        case 'critical': critical++; break;
        case 'high': high++; break;
        case 'medium': medium++; break;
        case 'info': info++; break;
      }

      allFindings.push(finding);

      // Scanner breakdown
      scannerBreakdown[result.scanner][finding.severity]++;

      // Dimension mapping (default to codeSafety for unknown scanners)
      const dim = DIMENSION_MAP[result.scanner] || 'codeSafety';
      dimensionFindings[dim].push(finding);
    }
  }

  const totalFindings = critical + high + medium + info;

  // Overall score uses confidence-weighted counts + interaction penalty
  const score = calculateScoreFromFindings(allFindings);
  const grade = scoreToGrade(score);

  // Per-dimension scores
  const dimensions = {
    codeSafety: buildDimensionScore(dimensionFindings.codeSafety),
    configSafety: buildDimensionScore(dimensionFindings.configSafety),
    defenseScore: buildDimensionScore(dimensionFindings.defenseScore),
  };

  // Overall grade uses weighted average of dimension scores
  // Code Safety 40% (direct attack surface: secrets, injection)
  // Config Safety 30% (MCP, permissions, channels)
  // Defense Score 30% (defense layers, red team resilience)
  const DIMENSION_WEIGHTS = { codeSafety: 0.4, configSafety: 0.3, defenseScore: 0.3 };

  let finalScore = score;
  let finalGrade = grade;

  const hasAnyDimensionFindings = allFindings.length > 0 &&
    Object.values(dimensionFindings).some(f => f.length > 0);

  if (hasAnyDimensionFindings) {
    const weightedScore = Math.round(
      dimensions.codeSafety.score * DIMENSION_WEIGHTS.codeSafety +
      dimensions.configSafety.score * DIMENSION_WEIGHTS.configSafety +
      dimensions.defenseScore.score * DIMENSION_WEIGHTS.defenseScore
    );
    finalScore = weightedScore;
    finalGrade = scoreToGrade(finalScore);
  }

  return {
    totalFindings,
    critical,
    high,
    medium,
    info,
    grade: finalGrade,
    score: finalScore,
    scannedFiles,
    duration,
    dimensions,
    scannerBreakdown,
  };
}

function buildDimensionScore(findings: Finding[]): { score: number; grade: string; findings: number } {
  const score = calculateScoreFromFindings(findings);
  return {
    score,
    grade: scoreToGrade(score),
    findings: findings.length,
  };
}

export function scoreToGrade(score: number): string {
  if (score >= 97) return 'A+';
  if (score >= 93) return 'A';
  if (score >= 90) return 'A-';
  if (score >= 87) return 'B+';
  if (score >= 83) return 'B';
  if (score >= 80) return 'B-';
  if (score >= 77) return 'C+';
  if (score >= 73) return 'C';
  if (score >= 70) return 'C-';
  if (score >= 67) return 'D+';
  if (score >= 63) return 'D';
  if (score >= 60) return 'D-';
  return 'F';
}
