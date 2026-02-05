import { isTestFileForScoring } from '../src/utils/file-utils';
import { calculateSummary } from '../src/utils/scorer';
import { Finding, ScanResult } from '../src/types';

describe('Test File Scoring Exclusion', () => {
  describe('isTestFileForScoring', () => {
    it('should match files in tests/ directory', () => {
      expect(isTestFileForScoring('/project/tests/foo.ts')).toBe(true);
      expect(isTestFileForScoring('/project/tests/unit/bar.js')).toBe(true);
    });

    it('should match files in __tests__/ directory', () => {
      expect(isTestFileForScoring('/project/__tests__/foo.ts')).toBe(true);
      expect(isTestFileForScoring('/project/src/__tests__/bar.js')).toBe(true);
    });

    it('should match *.test.* files', () => {
      expect(isTestFileForScoring('/project/src/foo.test.ts')).toBe(true);
      expect(isTestFileForScoring('/project/bar.test.js')).toBe(true);
    });

    it('should match *.spec.* files', () => {
      expect(isTestFileForScoring('/project/src/foo.spec.ts')).toBe(true);
      expect(isTestFileForScoring('/project/bar.spec.js')).toBe(true);
    });

    it('should not match regular source files', () => {
      expect(isTestFileForScoring('/project/src/index.ts')).toBe(false);
      expect(isTestFileForScoring('/project/lib/utils.js')).toBe(false);
    });

    it('should not match files with test in name but not pattern', () => {
      expect(isTestFileForScoring('/project/src/test-utils.ts')).toBe(false);
      expect(isTestFileForScoring('/project/src/testing.ts')).toBe(false);
    });
  });

  describe('Scoring exclusion for test file findings', () => {
    it('should not count test file findings in score', () => {
      const testFinding: Finding = {
        id: 'TEST-001',
        scanner: 'Prompt Injection Tester',
        severity: 'critical',
        title: '[TEST] Prompt injection pattern',
        description: 'Test pattern',
        recommendation: 'N/A',
        isTestFile: true,
      };

      const result: ScanResult = {
        scanner: 'Prompt Injection Tester',
        findings: [testFinding],
        scannedFiles: 1,
        duration: 10,
      };

      const summary = calculateSummary([result]);
      // Score should be 100 because test findings are excluded
      expect(summary.score).toBe(100);
      // But counts should still be reported
      expect(summary.critical).toBe(1);
    });

    it('should count non-test findings normally', () => {
      const realFinding: Finding = {
        id: 'REAL-001',
        scanner: 'Prompt Injection Tester',
        severity: 'critical',
        title: 'Real injection pattern',
        description: 'Real pattern',
        recommendation: 'Fix it',
        confidence: 'definite',
      };

      const result: ScanResult = {
        scanner: 'Prompt Injection Tester',
        findings: [realFinding],
        scannedFiles: 1,
        duration: 10,
      };

      const summary = calculateSummary([result]);
      expect(summary.score).toBeLessThan(100);
      expect(summary.critical).toBe(1);
    });

    it('should exclude Secret Leak Scanner INFO findings from score', () => {
      const infoFinding: Finding = {
        id: 'SL-INFO-001',
        scanner: 'Secret Leak Scanner',
        severity: 'info',
        title: 'Potential pattern',
        description: 'Low confidence',
        recommendation: 'Review',
        confidence: 'definite',
      };

      const result: ScanResult = {
        scanner: 'Secret Leak Scanner',
        findings: [infoFinding],
        scannedFiles: 1,
        duration: 10,
      };

      const summary = calculateSummary([result]);
      expect(summary.score).toBe(100);
      expect(summary.info).toBe(1);
    });

    it('should still count Secret Leak Scanner non-INFO findings', () => {
      const highFinding: Finding = {
        id: 'SL-HIGH-001',
        scanner: 'Secret Leak Scanner',
        severity: 'high',
        title: 'Secret found',
        description: 'High risk',
        recommendation: 'Fix',
        confidence: 'definite',
      };

      const result: ScanResult = {
        scanner: 'Secret Leak Scanner',
        findings: [highFinding],
        scannedFiles: 1,
        duration: 10,
      };

      const summary = calculateSummary([result]);
      expect(summary.score).toBeLessThan(100);
    });

    it('should handle mix of test and real findings', () => {
      const testFinding: Finding = {
        id: 'TEST-001',
        scanner: 'Prompt Injection Tester',
        severity: 'critical',
        title: '[TEST] Pattern',
        description: 'Test',
        recommendation: 'N/A',
        isTestFile: true,
      };

      const realFinding: Finding = {
        id: 'REAL-001',
        scanner: 'Prompt Injection Tester',
        severity: 'high',
        title: 'Real pattern',
        description: 'Real',
        recommendation: 'Fix',
        confidence: 'definite',
      };

      const result: ScanResult = {
        scanner: 'Prompt Injection Tester',
        findings: [testFinding, realFinding],
        scannedFiles: 2,
        duration: 10,
      };

      const summary = calculateSummary([result]);
      // Only the high finding should affect the score
      expect(summary.critical).toBe(1);
      expect(summary.high).toBe(1);
      // Score should reflect only the high finding, not the test critical
      expect(summary.score).toBeGreaterThan(90);
      expect(summary.score).toBeLessThan(100);
    });
  });
});
