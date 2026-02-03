import { ReportSummary, ScanResult } from '../types';

const SEVERITY_WEIGHTS = {
  critical: 25,
  high: 10,
  medium: 3,
  info: 0,
};

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
  const penalty = critical * SEVERITY_WEIGHTS.critical +
    high * SEVERITY_WEIGHTS.high +
    medium * SEVERITY_WEIGHTS.medium +
    info * SEVERITY_WEIGHTS.info;

  const score = Math.max(0, Math.min(100, 100 - penalty));
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
