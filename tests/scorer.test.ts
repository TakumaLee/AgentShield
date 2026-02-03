import { calculateSummary, scoreToGrade } from '../src/utils/scorer';
import { ScanResult } from '../src/types';

describe('Scorer', () => {
  test('returns A+ for no findings', () => {
    const results: ScanResult[] = [{
      scanner: 'test',
      findings: [],
      scannedFiles: 5,
      duration: 100,
    }];
    const summary = calculateSummary(results);
    expect(summary.grade).toBe('A+');
    expect(summary.score).toBe(100);
    expect(summary.totalFindings).toBe(0);
  });

  test('penalizes critical findings heavily', () => {
    const results: ScanResult[] = [{
      scanner: 'test',
      findings: [{
        id: 'test-1', scanner: 'test', severity: 'critical',
        title: 'test', description: 'test', recommendation: 'test',
      }],
      scannedFiles: 1,
      duration: 50,
    }];
    const summary = calculateSummary(results);
    expect(summary.score).toBe(75);
    expect(summary.critical).toBe(1);
  });

  test('F grade for many criticals', () => {
    const findings = Array.from({ length: 5 }, (_, i) => ({
      id: `test-${i}`, scanner: 'test', severity: 'critical' as const,
      title: 'test', description: 'test', recommendation: 'test',
    }));
    const summary = calculateSummary([{
      scanner: 'test', findings, scannedFiles: 1, duration: 50,
    }]);
    expect(summary.grade).toBe('F');
    expect(summary.score).toBe(0);
  });

  test('scoreToGrade covers all ranges', () => {
    expect(scoreToGrade(100)).toBe('A+');
    expect(scoreToGrade(95)).toBe('A');
    expect(scoreToGrade(91)).toBe('A-');
    expect(scoreToGrade(88)).toBe('B+');
    expect(scoreToGrade(85)).toBe('B');
    expect(scoreToGrade(80)).toBe('B-');
    expect(scoreToGrade(77)).toBe('C+');
    expect(scoreToGrade(73)).toBe('C');
    expect(scoreToGrade(70)).toBe('C-');
    expect(scoreToGrade(67)).toBe('D+');
    expect(scoreToGrade(63)).toBe('D');
    expect(scoreToGrade(60)).toBe('D-');
    expect(scoreToGrade(50)).toBe('F');
  });

  test('aggregates across multiple scanners', () => {
    const results: ScanResult[] = [
      {
        scanner: 'scanner1', scannedFiles: 3, duration: 100,
        findings: [
          { id: '1', scanner: 's1', severity: 'critical', title: '', description: '', recommendation: '' },
        ],
      },
      {
        scanner: 'scanner2', scannedFiles: 2, duration: 50,
        findings: [
          { id: '2', scanner: 's2', severity: 'high', title: '', description: '', recommendation: '' },
          { id: '3', scanner: 's2', severity: 'medium', title: '', description: '', recommendation: '' },
        ],
      },
    ];
    const summary = calculateSummary(results);
    expect(summary.totalFindings).toBe(3);
    expect(summary.critical).toBe(1);
    expect(summary.high).toBe(1);
    expect(summary.medium).toBe(1);
    expect(summary.scannedFiles).toBe(5);
    expect(summary.duration).toBe(150);
  });
});
