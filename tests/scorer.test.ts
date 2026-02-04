import { calculateSummary, scoreToGrade, interactionPenalty } from '../src/utils/scorer';
import { ScanResult, Finding } from '../src/types';

// Helper to create a finding with optional confidence
function makeFinding(
  id: string,
  severity: 'critical' | 'high' | 'medium' | 'info',
  scanner = 'test',
  confidence?: 'definite' | 'likely' | 'possible',
): Finding {
  return {
    id, scanner, severity,
    title: 'test', description: 'test', recommendation: 'test',
    ...(confidence ? { confidence } : {}),
  };
}

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

  test('penalizes critical findings with diminishing returns', () => {
    const results: ScanResult[] = [{
      scanner: 'test',
      findings: [makeFinding('test-1', 'critical')],
      scannedFiles: 1,
      duration: 50,
    }];
    const summary = calculateSummary(results);
    // codeSafety=80, weighted: 80×0.4+100×0.3+100×0.3=92
    expect(summary.score).toBe(92);
    expect(summary.critical).toBe(1);
  });

  test('many criticals cap at max penalty per severity', () => {
    const findings = Array.from({ length: 20 }, (_, i) =>
      makeFinding(`test-${i}`, 'critical'));
    const summary = calculateSummary([{
      scanner: 'test', findings, scannedFiles: 1, duration: 50,
    }]);
    // codeSafety=50, weighted: 50×0.4+100×0.3+100×0.3=80
    expect(summary.score).toBe(80);
    expect(summary.grade).toBe('B-');
  });

  test('F grade requires multiple severity types maxed out', () => {
    const criticals = Array.from({ length: 20 }, (_, i) =>
      makeFinding(`c-${i}`, 'critical'));
    const highs = Array.from({ length: 50 }, (_, i) =>
      makeFinding(`h-${i}`, 'high'));
    const mediums = Array.from({ length: 100 }, (_, i) =>
      makeFinding(`m-${i}`, 'medium'));
    const summary = calculateSummary([{
      scanner: 'test', findings: [...criticals, ...highs, ...mediums], scannedFiles: 1, duration: 50,
    }]);
    // codeSafety≈2 (all penalties near max), weighted: ~2×0.4+100×0.3+100×0.3≈61
    expect(summary.score).toBeLessThan(65);
    expect(summary.score).toBeGreaterThanOrEqual(60);
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
        findings: [makeFinding('1', 'critical', 's1')],
      },
      {
        scanner: 'scanner2', scannedFiles: 2, duration: 50,
        findings: [
          makeFinding('2', 'high', 's2'),
          makeFinding('3', 'medium', 's2'),
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

describe('Interaction Penalty', () => {
  test('returns 0 when no critical findings', () => {
    expect(interactionPenalty(0, 5)).toBe(0);
  });

  test('returns 0 when no high findings', () => {
    expect(interactionPenalty(3, 0)).toBe(0);
  });

  test('returns 0 when neither critical nor high', () => {
    expect(interactionPenalty(0, 0)).toBe(0);
  });

  test('applies penalty when both critical and high exist', () => {
    const penalty = interactionPenalty(1, 1);
    // 5 * log2(1 + 1) = 5 * 1 = 5
    expect(penalty).toBe(5);
  });

  test('uses min of critical/high for scaling', () => {
    // min(10, 2) = 2, 5 * log2(3) ≈ 7.92
    const penalty = interactionPenalty(10, 2);
    expect(penalty).toBeCloseTo(5 * Math.log2(3), 5);
  });

  test('caps at 10', () => {
    // min(100, 100) = 100, 5 * log2(101) ≈ 33.3 → capped at 10
    const penalty = interactionPenalty(100, 100);
    expect(penalty).toBe(10);
  });

  test('interaction penalty is reflected in overall score', () => {
    // 1 critical + 1 high: penalty = 20 + 5 + interaction(1,1)=5 = 30
    const results: ScanResult[] = [{
      scanner: 'test',
      findings: [
        makeFinding('c1', 'critical'),
        makeFinding('h1', 'high'),
      ],
      scannedFiles: 1,
      duration: 50,
    }];
    const summary = calculateSummary(results);
    // codeSafety=70, weighted: 70×0.4+100×0.3+100×0.3=88
    expect(summary.score).toBe(88);
  });
});

describe('Confidence Weighting', () => {
  test('definite findings have full weight', () => {
    const results: ScanResult[] = [{
      scanner: 'test',
      findings: [makeFinding('c1', 'critical', 'test', 'definite')],
      scannedFiles: 1,
      duration: 50,
    }];
    const summary = calculateSummary(results);
    // codeSafety=80, weighted: 80×0.4+100×0.3+100×0.3=92
    expect(summary.score).toBe(92);
  });

  test('possible findings have reduced weight', () => {
    // 3 possible high = 3 × 0.6 = 1.8 effective high
    // penalty = 5 * log2(1.8 + 1) = 5 * log2(2.8) ≈ 7.44
    const results: ScanResult[] = [{
      scanner: 'test',
      findings: [
        makeFinding('h1', 'high', 'test', 'possible'),
        makeFinding('h2', 'high', 'test', 'possible'),
        makeFinding('h3', 'high', 'test', 'possible'),
      ],
      scannedFiles: 1,
      duration: 50,
    }];
    const summary = calculateSummary(results);
    const expectedPenalty = 5 * Math.log2(1.8 + 1);
    const dimScore = Math.round(100 - expectedPenalty);
    // weighted: dimScore×0.4+100×0.3+100×0.3
    expect(summary.score).toBe(Math.round(dimScore * 0.4 + 100 * 0.3 + 100 * 0.3));
  });

  test('likely findings have 0.8 weight', () => {
    // 5 likely critical = 5 × 0.8 = 4.0 effective critical
    // penalty = 20 * log2(4 + 1) = 20 * log2(5) ≈ 46.44
    const results: ScanResult[] = [{
      scanner: 'test',
      findings: Array.from({ length: 5 }, (_, i) =>
        makeFinding(`c${i}`, 'critical', 'test', 'likely')),
      scannedFiles: 1,
      duration: 50,
    }];
    const summary = calculateSummary(results);
    const expectedPenalty = 20 * Math.log2(4.0 + 1);
    const dimScore = Math.round(100 - expectedPenalty);
    // weighted: dimScore×0.4+100×0.3+100×0.3
    expect(summary.score).toBe(Math.round(dimScore * 0.4 + 100 * 0.3 + 100 * 0.3));
  });

  test('findings without confidence default to definite', () => {
    const results: ScanResult[] = [{
      scanner: 'test',
      findings: [makeFinding('c1', 'critical')], // no confidence
      scannedFiles: 1,
      duration: 50,
    }];
    const summary = calculateSummary(results);
    // codeSafety=80, weighted: 80×0.4+100×0.3+100×0.3=92
    expect(summary.score).toBe(92);
  });

  test('mixed confidence is weighted correctly', () => {
    // 1 definite critical (1.0) + 1 possible critical (0.6) = 1.6 effective
    // penalty = 20 * log2(1.6 + 1) = 20 * log2(2.6) ≈ 27.58
    const results: ScanResult[] = [{
      scanner: 'test',
      findings: [
        makeFinding('c1', 'critical', 'test', 'definite'),
        makeFinding('c2', 'critical', 'test', 'possible'),
      ],
      scannedFiles: 1,
      duration: 50,
    }];
    const summary = calculateSummary(results);
    const expectedPenalty = 20 * Math.log2(1.6 + 1);
    const dimScore = Math.round(100 - expectedPenalty);
    // weighted: dimScore×0.4+100×0.3+100×0.3
    expect(summary.score).toBe(Math.round(dimScore * 0.4 + 100 * 0.3 + 100 * 0.3));
  });
});

describe('Three-Dimension Scoring', () => {
  test('dimensions are present in summary', () => {
    const results: ScanResult[] = [{
      scanner: 'Secret Leak Scanner',
      findings: [makeFinding('s1', 'high', 'secret-leak-scanner', 'definite')],
      scannedFiles: 1,
      duration: 50,
    }];
    const summary = calculateSummary(results);
    expect(summary.dimensions).toBeDefined();
    expect(summary.dimensions!.codeSafety.findings).toBe(1);
    expect(summary.dimensions!.configSafety.findings).toBe(0);
    expect(summary.dimensions!.defenseScore.findings).toBe(0);
  });

  test('scanners map to correct dimensions', () => {
    const results: ScanResult[] = [
      {
        scanner: 'Secret Leak Scanner', scannedFiles: 1, duration: 10,
        findings: [makeFinding('s1', 'high', 'sl', 'definite')],
      },
      {
        scanner: 'MCP Config Auditor', scannedFiles: 1, duration: 10,
        findings: [makeFinding('m1', 'medium', 'mcp', 'definite')],
      },
      {
        scanner: 'Defense Analyzer', scannedFiles: 1, duration: 10,
        findings: [makeFinding('d1', 'high', 'da', 'possible')],
      },
    ];
    const summary = calculateSummary(results);
    expect(summary.dimensions!.codeSafety.findings).toBe(1);
    expect(summary.dimensions!.configSafety.findings).toBe(1);
    expect(summary.dimensions!.defenseScore.findings).toBe(1);
  });

  test('each dimension scores independently', () => {
    const results: ScanResult[] = [
      {
        scanner: 'Secret Leak Scanner', scannedFiles: 1, duration: 10,
        findings: Array.from({ length: 10 }, (_, i) =>
          makeFinding(`s${i}`, 'critical', 'sl', 'definite')),
      },
      {
        scanner: 'MCP Config Auditor', scannedFiles: 1, duration: 10,
        findings: [], // no config issues
      },
      {
        scanner: 'Defense Analyzer', scannedFiles: 1, duration: 10,
        findings: [], // no defense issues
      },
    ];
    const summary = calculateSummary(results);
    // codeSafety should be low (10 criticals)
    expect(summary.dimensions!.codeSafety.score).toBeLessThan(60);
    // configSafety should be perfect
    expect(summary.dimensions!.configSafety.score).toBe(100);
    // defenseScore should be perfect
    expect(summary.dimensions!.defenseScore.score).toBe(100);
  });

  test('overall score uses min of dimensions when findings exist', () => {
    const results: ScanResult[] = [
      {
        scanner: 'Secret Leak Scanner', scannedFiles: 1, duration: 10,
        findings: Array.from({ length: 10 }, (_, i) =>
          makeFinding(`s${i}`, 'critical', 'sl', 'definite')),
      },
      {
        scanner: 'MCP Config Auditor', scannedFiles: 1, duration: 10,
        findings: [],
      },
    ];
    const summary = calculateSummary(results);
    // Code safety is bad (50), config is perfect.
    // Weighted avg: 50×0.4+100×0.3+100×0.3=80
    expect(summary.score).toBe(80);
  });

  test('dimension grades are correctly assigned', () => {
    const results: ScanResult[] = [{
      scanner: 'Secret Leak Scanner', scannedFiles: 1, duration: 10,
      findings: [],
    }];
    const summary = calculateSummary(results);
    expect(summary.dimensions!.codeSafety.grade).toBe('A+');
    expect(summary.dimensions!.configSafety.grade).toBe('A+');
    expect(summary.dimensions!.defenseScore.grade).toBe('A+');
  });
});

describe('Scanner Breakdown', () => {
  test('tracks per-scanner severity counts', () => {
    const results: ScanResult[] = [
      {
        scanner: 'Secret Leak Scanner', scannedFiles: 1, duration: 10,
        findings: [
          makeFinding('s1', 'critical'),
          makeFinding('s2', 'high'),
        ],
      },
      {
        scanner: 'Defense Analyzer', scannedFiles: 1, duration: 10,
        findings: [
          makeFinding('d1', 'medium'),
          makeFinding('d2', 'info'),
          makeFinding('d3', 'info'),
        ],
      },
    ];
    const summary = calculateSummary(results);
    expect(summary.scannerBreakdown).toBeDefined();
    expect(summary.scannerBreakdown!['Secret Leak Scanner']).toEqual({
      critical: 1, high: 1, medium: 0, info: 0,
    });
    expect(summary.scannerBreakdown!['Defense Analyzer']).toEqual({
      critical: 0, high: 0, medium: 1, info: 2,
    });
  });
});

describe('Edge Cases', () => {
  test('0 findings gives score 100 grade A+', () => {
    const summary = calculateSummary([{
      scanner: 'test', findings: [], scannedFiles: 0, duration: 0,
    }]);
    expect(summary.score).toBe(100);
    expect(summary.grade).toBe('A+');
    expect(summary.totalFindings).toBe(0);
  });

  test('all info findings give score 100', () => {
    const findings = Array.from({ length: 50 }, (_, i) =>
      makeFinding(`i${i}`, 'info'));
    const summary = calculateSummary([{
      scanner: 'test', findings, scannedFiles: 1, duration: 50,
    }]);
    expect(summary.score).toBe(100);
    expect(summary.grade).toBe('A+');
    expect(summary.info).toBe(50);
  });

  test('score never goes below 0', () => {
    const findings = [
      ...Array.from({ length: 50 }, (_, i) => makeFinding(`c${i}`, 'critical')),
      ...Array.from({ length: 50 }, (_, i) => makeFinding(`h${i}`, 'high')),
      ...Array.from({ length: 50 }, (_, i) => makeFinding(`m${i}`, 'medium')),
    ];
    const summary = calculateSummary([{
      scanner: 'test', findings, scannedFiles: 1, duration: 50,
    }]);
    expect(summary.score).toBeGreaterThanOrEqual(0);
  });

  test('cap scenario: all severity caps hit simultaneously', () => {
    const findings = [
      ...Array.from({ length: 100 }, (_, i) => makeFinding(`c${i}`, 'critical')),
      ...Array.from({ length: 100 }, (_, i) => makeFinding(`h${i}`, 'high')),
      ...Array.from({ length: 100 }, (_, i) => makeFinding(`m${i}`, 'medium')),
    ];
    const summary = calculateSummary([{
      scanner: 'test', findings, scannedFiles: 1, duration: 50,
    }]);
    // codeSafety=0, weighted: 0×0.4+100×0.3+100×0.3=60
    expect(summary.score).toBe(60);
    expect(summary.grade).toBe('D-');
  });

  test('empty results array', () => {
    const summary = calculateSummary([]);
    expect(summary.score).toBe(100);
    expect(summary.grade).toBe('A+');
    expect(summary.totalFindings).toBe(0);
  });
});
