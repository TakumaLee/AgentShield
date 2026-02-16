import { Scanner, ScanResult, Finding, Severity } from '../types';
import { walkFiles, FileEntry } from '../utils/file-walker';

export class VisualPromptInjectionScanner implements Scanner {
  name = 'Visual Prompt Injection Scanner';
  description = 'Detects suspicious image processing + LLM vision API combinations that may be vulnerable to visual prompt injection attacks';

  async scan(targetPath: string): Promise<ScanResult> {
    const start = Date.now();
    const findings: Finding[] = [];
    let scannedFiles = 0;

    // Walk all code files
    for await (const file of walkFiles(targetPath)) {
      if (!this.isCodeFile(file.path)) continue;
      
      scannedFiles++;
      const fileFindings = this.scanFile(file);
      findings.push(...fileFindings);
    }

    return {
      scanner: this.name,
      findings,
      scannedFiles,
      duration: Date.now() - start,
    };
  }

  private isCodeFile(filePath: string): boolean {
    return /\.(ts|js|tsx|jsx|py|go|rs|java)$/.test(filePath);
  }

  private scanFile(file: FileEntry): Finding[] {
    const findings: Finding[] = [];
    const content = file.content;
    const filePath = file.path;

    // Pattern 1: Vision API usage without input validation
    findings.push(...this.detectVisionAPIUsage(content, filePath));

    // Pattern 2: Image processing with external sources
    findings.push(...this.detectUnsafeImageSources(content, filePath));

    // Pattern 3: Missing content moderation on vision inputs
    findings.push(...this.detectMissingModeration(content, filePath));

    return findings;
  }

  private detectVisionAPIUsage(content: string, filePath: string): Finding[] {
    const findings: Finding[] = [];
    const lines = content.split('\n');

    // Vision API patterns
    const visionAPIs = [
      { pattern: /openai.*vision|gpt-4.*vision/i, api: 'OpenAI GPT-4 Vision' },
      { pattern: /anthropic.*vision|claude.*vision/i, api: 'Anthropic Claude Vision' },
      { pattern: /gemini.*vision|google.*vision/i, api: 'Google Gemini Vision' },
      { pattern: /llava|blip|clip/i, api: 'Open Source Vision Model' },
      { pattern: /vision.*api|image.*analyze|ocr.*api/i, api: 'Generic Vision API' },
    ];

    // Validation patterns (good practices)
    const validationPatterns = [
      /sanitize.*image|validate.*image|check.*image/i,
      /content.*moderation|safety.*filter/i,
      /image.*hash|image.*signature/i,
      /whitelist|allowlist|trusted.*source/i,
    ];

    const hasValidation = validationPatterns.some(p => p.test(content));

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];

      for (const { pattern, api } of visionAPIs) {
        if (pattern.test(line)) {
          const severity: Severity = hasValidation ? 'medium' : 'high';
          const id = `VPI-001-${filePath}-${i + 1}`;

          if (!findings.some(f => f.id === id)) {
            findings.push({
              id,
              scanner: 'visual-prompt-injection-scanner',
              severity,
              title: `Visual Prompt Injection Risk: ${api} without validation`,
              description: `Detected ${api} usage. ${hasValidation ? 'Some validation exists but verify it covers visual prompt injection.' : 'No input validation detected for image content.'} Line: "${line.trim().substring(0, 100)}"`,
              file: filePath,
              line: i + 1,
              confidence: hasValidation ? 'possible' : 'likely',
              recommendation: 'Implement image content validation: 1) Hash-based verification for trusted sources, 2) Content moderation API, 3) Strip embedded text/metadata from images, 4) Rate limiting per user/source',
            });
          }
        }
      }
    }

    return findings;
  }

  private detectUnsafeImageSources(content: string, filePath: string): Finding[] {
    const findings: Finding[] = [];
    const lines = content.split('\n');

    // Patterns for loading images from untrusted sources
    const unsafeSourcePatterns = [
      { pattern: /fetch.*image|download.*image|http.*image/i, source: 'HTTP fetch' },
      { pattern: /user.*upload|file.*upload|multipart/i, source: 'User upload' },
      { pattern: /url.*param|query.*image|request.*image/i, source: 'URL parameter' },
      { pattern: /s3.*get|blob.*download|storage.*read/i, source: 'Cloud storage' },
    ];

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];

      for (const { pattern, source } of unsafeSourcePatterns) {
        if (pattern.test(line)) {
          // Check if this line is near vision API usage (within 20 lines)
          const nearbyLines = lines.slice(Math.max(0, i - 10), Math.min(lines.length, i + 10)).join('\n');
          const hasVisionAPI = /vision|gpt-4|claude|gemini|analyze.*image/i.test(nearbyLines);

          if (hasVisionAPI) {
            const id = `VPI-002-${filePath}-${i + 1}`;
            if (!findings.some(f => f.id === id)) {
              findings.push({
                id,
                scanner: 'visual-prompt-injection-scanner',
                severity: 'high',
                title: `Unsafe Image Source: ${source} + Vision API`,
                description: `Images from ${source} processed by vision model without apparent validation. Attackers can inject instructions via steganography, embedded text, or OCR-readable content. Line: "${line.trim().substring(0, 100)}"`,
                file: filePath,
                line: i + 1,
                confidence: 'likely',
                recommendation: 'Validate image sources: 1) Accept only from trusted domains/users, 2) Re-encode/sanitize images before processing, 3) Strip EXIF and metadata, 4) Implement content hash verification',
              });
            }
          }
        }
      }
    }

    return findings;
  }

  private detectMissingModeration(content: string, filePath: string): Finding[] {
    const findings: Finding[] = [];
    const lines = content.split('\n');

    // Check if vision API exists but no moderation
    const hasVisionAPI = /vision|gpt-4.*vision|claude.*vision|analyze.*image/i.test(content);
    const hasModerationAPI = /moderation|content.*safety|perspective.*api|rekognition/i.test(content);
    const hasTextExtraction = /ocr|tesseract|text.*from.*image|extract.*text/i.test(content);

    if (hasVisionAPI && !hasModerationAPI) {
      // Find the first vision API usage line
      for (let i = 0; i < lines.length; i++) {
        if (/vision|analyze.*image|process.*image/i.test(lines[i])) {
          const id = `VPI-003-${filePath}-${i + 1}`;
          if (!findings.some(f => f.id === id)) {
            findings.push({
              id,
              scanner: 'visual-prompt-injection-scanner',
              severity: 'medium',
              title: 'Missing Content Moderation for Vision Input',
              description: `Vision API usage detected without content moderation. ${hasTextExtraction ? 'Text extraction present - verify OCR output is sanitized.' : ''} Malicious images can contain hidden instructions readable by vision models but invisible to humans.`,
              file: filePath,
              line: i + 1,
              confidence: 'likely',
              recommendation: 'Add content moderation: 1) Use moderation API (OpenAI Moderation, Perspective API), 2) Sanitize extracted text for prompt injection patterns, 3) Implement image hashing to detect known malicious images',
            });
          }
          break; // Only report once per file
        }
      }
    }

    return findings;
  }
}
