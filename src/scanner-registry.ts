import { Scanner, ScanReport, ScanResult } from './types';
import { calculateSummary } from './utils/scorer';

export class ScannerRegistry {
  private scanners: Scanner[] = [];

  register(scanner: Scanner): void {
    this.scanners.push(scanner);
  }

  getScanners(): Scanner[] {
    return [...this.scanners];
  }

  async runAll(targetDir: string): Promise<ScanReport> {
    const timestamp = new Date().toISOString();
    const results: ScanResult[] = [];

    for (const scanner of this.scanners) {
      const result = await scanner.scan(targetDir);
      results.push(result);
    }

    const summary = calculateSummary(results);

    return {
      target: targetDir,
      timestamp,
      results,
      summary,
      totalFindings: summary.totalFindings,
      criticalCount: summary.critical,
      highCount: summary.high,
      mediumCount: summary.medium,
      lowCount: summary.info,
    };
  }
}
