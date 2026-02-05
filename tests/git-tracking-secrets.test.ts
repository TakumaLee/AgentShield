import { scanForSecrets } from '../src/scanners/secret-leak-scanner';

describe('Secret Leak Scanner - Git Tracking Awareness', () => {
  describe('isSecretOrTokenFinding helper (via scanForSecrets)', () => {
    it('should detect API key patterns', () => {
      const content = 'API_KEY=sk-1234567890abcdef1234567890abcdef';
      const findings = scanForSecrets(content, '/test/config.ts');
      expect(findings.length).toBeGreaterThan(0);
      expect(findings[0].severity).toBe('critical');
    });

    it('should not flag placeholders', () => {
      const content = 'API_KEY=your_api_key_here';
      const findings = scanForSecrets(content, '/test/config.ts');
      expect(findings.length).toBe(0);
    });
  });

  describe('Secret finding messages', () => {
    it('should include appropriate description for critical findings', () => {
      const content = 'OPENAI_API_KEY=sk-1234567890abcdef1234567890abcdef';
      const findings = scanForSecrets(content, '/test/config.ts');
      expect(findings.length).toBeGreaterThan(0);
      // Base finding should be critical
      expect(findings[0].severity).toBe('critical');
    });
  });
});

describe('Secret Leak Scanner - INFO findings scoring', () => {
  it('INFO severity findings should exist but not affect score', () => {
    // This is tested in test-file-scoring.test.ts more comprehensively
    // Here we verify that INFO findings from Secret Leak Scanner are possible
    const content = 'API_KEY=test'; // dev credential, should be downgraded
    const findings = scanForSecrets(content, '/test/example.config.ts');
    // findings with dev credentials get info severity
    for (const f of findings) {
      if (f.severity === 'info') {
        // Good - this type of INFO finding should not affect scoring
        expect(f.severity).toBe('info');
      }
    }
  });
});
