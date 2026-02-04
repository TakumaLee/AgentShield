import * as path from 'path';
import chalk from 'chalk';
import { ScanReport, ScannerModule, ScanContext } from './types';
import { promptInjectionTester } from './scanners/prompt-injection-tester';
import { mcpConfigAuditor } from './scanners/mcp-config-auditor';
import { secretLeakScanner } from './scanners/secret-leak-scanner';
import { permissionAnalyzer } from './scanners/permission-analyzer';
import { defenseAnalyzer } from './scanners/defense-analyzer';
import { skillAuditor } from './scanners/skill-auditor';
import { redTeamSimulator } from './scanners/red-team-simulator';
import { channelSurfaceAuditor } from './scanners/channel-surface-auditor';
import { agentConfigAuditor } from './scanners/agent-config-auditor';
import { calculateSummary } from './utils/scorer';
import { printReport, writeJsonReport } from './utils/reporter';
import { fileExists } from './utils/file-utils';

const SCANNERS: ScannerModule[] = [
  promptInjectionTester,
  mcpConfigAuditor,
  secretLeakScanner,
  permissionAnalyzer,
  defenseAnalyzer,
  skillAuditor,
  redTeamSimulator,
  channelSurfaceAuditor,
  agentConfigAuditor,
];

export type ProfileType = 'agent' | 'general' | 'mobile';

/**
 * Profile definitions: which scanners to run for each profile.
 * Scanner names must match ScannerModule.name exactly.
 */
const PROFILE_SCANNERS: Record<ProfileType, string[] | null> = {
  agent: null, // all scanners
  general: ['Secret Leak Scanner', 'Permission Analyzer', 'Skill Auditor'],
  mobile: ['Secret Leak Scanner', 'Permission Analyzer'],
};

export function filterScannersByProfile(scanners: ScannerModule[], profile: ProfileType): ScannerModule[] {
  const allowed = PROFILE_SCANNERS[profile];
  if (allowed === null) return scanners;
  return scanners.filter(s => allowed.includes(s.name));
}

export interface ScanOptions {
  output?: string;
  json?: boolean;
  scanners?: string[];
  verbose?: boolean;
  exclude?: string[];
  profile?: ProfileType;
  context?: ScanContext;
  includeVendored?: boolean;
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
  if (options.profile && options.profile !== 'agent') {
    console.log(chalk.gray(`  Profile: ${options.profile}`));
  }
  if (options.context && options.context !== 'app') {
    console.log(chalk.gray(`  Context: ${options.context}`));
  }
  if (options.exclude && options.exclude.length > 0) {
    console.log(chalk.gray(`  Exclude: ${options.exclude.join(', ')}`));
  }
  console.log('');

  // Filter scanners: --scanners takes priority over --profile
  let activeScanners = SCANNERS;
  if (options.scanners && options.scanners.length > 0) {
    activeScanners = SCANNERS.filter(s =>
      options.scanners!.some(name =>
        s.name.toLowerCase().includes(name.toLowerCase())
      )
    );
  } else if (options.profile) {
    activeScanners = filterScannersByProfile(SCANNERS, options.profile);
  }

  // Scanner options (exclude patterns + context + vendored)
  const scannerOptions: { exclude?: string[]; context?: ScanContext; includeVendored?: boolean } = {};
  if (options.exclude && options.exclude.length > 0) {
    scannerOptions.exclude = options.exclude;
  }
  if (options.context) {
    scannerOptions.context = options.context;
  }
  if (options.includeVendored) {
    scannerOptions.includeVendored = true;
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

    const hasOptions = scannerOptions.exclude || scannerOptions.context || scannerOptions.includeVendored;
    const result = await scanner.scan(absPath, hasOptions ? scannerOptions : undefined);
    results.push(result);

    // Update with result
    const findingsColor = result.findings.length > 0 ? chalk.yellow(result.findings.length) : chalk.green('0');
    process.stdout.write(`\r  ${bar} ${pct}% · ${scanner.name} ${chalk.gray('→')} ${findingsColor} findings ${chalk.gray(`(${result.duration}ms)`)}   \n`);
  }

  // Build report
  const report: ScanReport = {
    version: '0.3.0',
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
