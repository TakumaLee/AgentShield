import * as fs from 'fs';
import * as path from 'path';
import chalk from 'chalk';
import { ScanReport, Finding, Severity } from '../types';

const SEVERITY_ICONS: Record<Severity, string> = {
  critical: '🔴',
  high: '🟠',
  medium: '🟡',
  info: '🔵',
};

const SEVERITY_COLORS: Record<Severity, (text: string) => string> = {
  critical: chalk.red.bold,
  high: chalk.hex('#FF8C00').bold,
  medium: chalk.yellow,
  info: chalk.blue,
};

export function printReport(report: ScanReport): void {
  console.log('');
  console.log(chalk.bold.cyan('╔══════════════════════════════════════════════════════════╗'));
  console.log(chalk.bold.cyan('║') + chalk.bold.white('  🛡️  AgentShield Security Report                        ') + chalk.bold.cyan('║'));
  console.log(chalk.bold.cyan('╚══════════════════════════════════════════════════════════╝'));
  console.log('');
  console.log(chalk.gray(`  Target:    ${report.target}`));
  console.log(chalk.gray(`  Timestamp: ${report.timestamp}`));
  console.log(chalk.gray(`  Version:   ${report.version}`));
  console.log('');

  if (report.summary.totalFindings === 0) {
    console.log(chalk.green.bold('  ✅ No vulnerabilities found! Your agent looks secure.'));
    console.log('');
  } else {
    // Group findings by scanner
    for (const result of report.results) {
      if (result.findings.length === 0) continue;

      console.log(chalk.bold.white(`  ── ${result.scanner} ──`));
      console.log(chalk.gray(`     Scanned ${result.scannedFiles} files in ${result.duration}ms`));
      console.log('');

      for (const finding of result.findings) {
        printFinding(finding);
      }
      console.log('');
    }
  }

  // Summary bar
  printSummaryBar(report);
}

function printFinding(finding: Finding): void {
  const icon = SEVERITY_ICONS[finding.severity];
  const colorFn = SEVERITY_COLORS[finding.severity];
  const sevLabel = colorFn(finding.severity.toUpperCase().padEnd(8));

  console.log(`  ${icon} ${sevLabel} ${chalk.white.bold(finding.title)}`);
  console.log(chalk.gray(`     ${finding.description}`));
  if (finding.file) {
    const loc = finding.line ? `${finding.file}:${finding.line}` : finding.file;
    console.log(chalk.gray(`     📁 ${loc}`));
  }
  console.log(chalk.green(`     💡 ${finding.recommendation}`));
  console.log('');
}

function printSummaryBar(report: ScanReport): void {
  const s = report.summary;
  console.log(chalk.bold.cyan('  ─────────────────────────────────────────────────────'));
  console.log('');

  // Grade display
  const gradeColor = s.score >= 80 ? chalk.green.bold :
    s.score >= 60 ? chalk.yellow.bold : chalk.red.bold;

  console.log(`  ${chalk.bold('Security Grade:')} ${gradeColor(s.grade)} ${chalk.gray(`(${s.score}/100)`)}`);
  console.log('');

  // Finding counts
  const counts = [
    s.critical > 0 ? `${SEVERITY_ICONS.critical} ${s.critical} Critical` : null,
    s.high > 0 ? `${SEVERITY_ICONS.high} ${s.high} High` : null,
    s.medium > 0 ? `${SEVERITY_ICONS.medium} ${s.medium} Medium` : null,
    s.info > 0 ? `${SEVERITY_ICONS.info} ${s.info} Info` : null,
  ].filter(Boolean);

  if (counts.length > 0) {
    console.log(`  ${chalk.bold('Findings:')} ${counts.join('  ')}`);
  } else {
    console.log(`  ${chalk.bold('Findings:')} ${chalk.green('None')}`);
  }

  console.log(`  ${chalk.bold('Files Scanned:')} ${s.scannedFiles}`);
  if (s.ignoredFiles && s.ignoredFiles > 0) {
    console.log(`  ${chalk.bold('Files Ignored:')} ${s.ignoredFiles} ${chalk.gray('(by .agentshieldignore)')}`);
  }
  console.log(`  ${chalk.bold('Duration:')} ${s.duration}ms`);
  console.log('');

  // Dimension scores
  if (s.dimensions) {
    console.log(`  ${chalk.bold('Dimensions:')}`);
    const dims = [
      { label: 'Code Safety', data: s.dimensions.codeSafety },
      { label: 'Config Safety', data: s.dimensions.configSafety },
      { label: 'Defense Score', data: s.dimensions.defenseScore },
    ];
    for (const dim of dims) {
      const dimColor = dim.data.score >= 80 ? chalk.green :
        dim.data.score >= 60 ? chalk.yellow : chalk.red;
      console.log(`    ${dim.label.padEnd(15)} ${dimColor(dim.data.grade)} ${chalk.gray(`(${dim.data.score}/100)`)} ${chalk.gray(`${dim.data.findings} findings`)}`);
    }
    console.log('');
  }

  // Per-scanner breakdown
  if (s.scannerBreakdown) {
    console.log(`  ${chalk.bold('Per-Scanner Breakdown:')}`);
    for (const [scanner, counts] of Object.entries(s.scannerBreakdown)) {
      const parts = [
        counts.critical > 0 ? `${SEVERITY_ICONS.critical}${counts.critical}` : null,
        counts.high > 0 ? `${SEVERITY_ICONS.high}${counts.high}` : null,
        counts.medium > 0 ? `${SEVERITY_ICONS.medium}${counts.medium}` : null,
        counts.info > 0 ? `${SEVERITY_ICONS.info}${counts.info}` : null,
      ].filter(Boolean);
      const total = counts.critical + counts.high + counts.medium + counts.info;
      if (total > 0) {
        console.log(`    ${scanner.padEnd(26)} ${parts.join(' ')}`);
      }
    }
    console.log('');
  }

  // Recommendations
  if (s.critical > 0) {
    console.log(chalk.red.bold('  ⚠️  CRITICAL issues found! Address these immediately.'));
  }
  if (s.high > 0) {
    console.log(chalk.hex('#FF8C00')('  ⚠️  High severity issues require attention.'));
  }
  if (s.score >= 90) {
    console.log(chalk.green('  ✨ Great security posture! Keep it up.'));
  }

  console.log('');
}

export function writeJsonReport(report: ScanReport, outputPath: string): void {
  const dir = path.dirname(outputPath);
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
  fs.writeFileSync(outputPath, JSON.stringify(report, null, 2), 'utf-8');
  console.log(chalk.gray(`  📄 JSON report saved to: ${outputPath}`));
  console.log('');
}
