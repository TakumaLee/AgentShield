import { ReportSummary, ScanResult } from '../types';

// Diminishing returns: first findings of each severity hurt more,
// but additional ones have less impact (logarithmic scaling)
const SEVERITY_BASE_PENALTY = {
  critical: 15,  // first critical = -15, but 10th critical ≠ -150
  high: 5,
  medium: 1.5,
  info: 0,
};

// Cap per severity so one category can't tank the entire score
const SEVERITY_MAX_PENALTY = {
  critical: 40,
  high: 30,
  medium: 15,
  info: 0,
};

function diminishingPenalty(count: number, basePenalty: number, maxPenalty: number): number {
  if (count === 0) return 0;
  // log curve: rapid initial penalty, diminishing returns
  const raw = basePenalty * Math.log2(count + 1);
  return Math.min(raw, maxPenalty);
}

export function calculateSummary(results: ScanResult[]): ReportSummary {
  let critical = 0;
  let high = 0;
  let medium = 0;
  let info = 0;
  let scannedFiles = 0;
  let duration = 0;

  for (const result of results) {
    scannedFiles += result.scannedFiles;
    duration += result.duration;
    for (const finding of result.findings) {
      switch (finding.severity) {
        case 'critical': critical++; break;
        case 'high': high++; break;
        case 'medium': medium++; break;
        case 'info': info++; break;
      }
    }
  }

  const totalFindings = critical + high + medium + info;

  const penalty =
    diminishingPenalty(critical, SEVERITY_BASE_PENALTY.critical, SEVERITY_MAX_PENALTY.critical) +
    diminishingPenalty(high, SEVERITY_BASE_PENALTY.high, SEVERITY_MAX_PENALTY.high) +
    diminishingPenalty(medium, SEVERITY_BASE_PENALTY.medium, SEVERITY_MAX_PENALTY.medium);

  const score = Math.max(0, Math.min(100, Math.round(100 - penalty)));
  const grade = scoreToGrade(score);

  return {
    totalFindings,
    critical,
    high,
    medium,
    info,
    grade,
    score,
    scannedFiles,
    duration,
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
