import * as path from 'path';
import chalk from 'chalk';
import { ScanReport, ScannerModule } from './types';
import { promptInjectionTester } from './scanners/prompt-injection-tester';
import { mcpConfigAuditor } from './scanners/mcp-config-auditor';
import { secretLeakScanner } from './scanners/secret-leak-scanner';
import { permissionAnalyzer } from './scanners/permission-analyzer';
import { calculateSummary } from './utils/scorer';
import { printReport, writeJsonReport } from './utils/reporter';
import { fileExists } from './utils/file-utils';

const SCANNERS: ScannerModule[] = [
  promptInjectionTester,
  mcpConfigAuditor,
  secretLeakScanner,
  permissionAnalyzer,
];

export interface ScanOptions {
  output?: string;
  json?: boolean;
  scanners?: string[];
  verbose?: boolean;
}

export async function runScan(targetPath: string, options: ScanOptions = {}): Promise<ScanReport> {
  const absPath = path.resolve(targetPath);

  if (!fileExists(absPath)) {
    console.error(chalk.red(`\n  ❌ Target path not found: ${absPath}\n`));
    process.exit(1);
  }

  console.log('');
  console.log(chalk.cyan('  🛡️  AgentShield scanning...'));
  console.log(chalk.gray(`  Target: ${absPath}`));
  console.log('');

  // Filter scanners if specified
  let activeScanners = SCANNERS;
  if (options.scanners && options.scanners.length > 0) {
    activeScanners = SCANNERS.filter(s =>
      options.scanners!.some(name =>
        s.name.toLowerCase().includes(name.toLowerCase())
      )
    );
  }

  // Run all scanners with progress
  const results = [];
  const total = activeScanners.length;
  for (let i = 0; i < total; i++) {
    const scanner = activeScanners[i];
    const step = i + 1;
    const pct = Math.round((step / total) * 100);
    const filled = Math.round((step / total) * 20);
    const empty = 20 - filled;
    const bar = chalk.green('█'.repeat(filled)) + chalk.gray('░'.repeat(empty));

    // Clear line and print progress
    process.stdout.write(`\r  ${bar} ${pct}% · ${scanner.name}...`);

    const result = await scanner.scan(absPath);
    results.push(result);

    // Update with result
    const findingsColor = result.findings.length > 0 ? chalk.yellow(result.findings.length) : chalk.green('0');
    process.stdout.write(`\r  ${bar} ${pct}% · ${scanner.name} ${chalk.gray('→')} ${findingsColor} findings ${chalk.gray(`(${result.duration}ms)`)}   \n`);
  }

  // Build report
  const report: ScanReport = {
    version: '0.1.0',
    timestamp: new Date().toISOString(),
    target: absPath,
    results,
    summary: calculateSummary(results),
  };

  // Output
  printReport(report);

  if (options.json || options.output) {
    const outputPath = options.output || path.join(absPath, 'agentshield-report.json');
    writeJsonReport(report, outputPath);
  }

  return report;
}
