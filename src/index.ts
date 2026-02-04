#!/usr/bin/env node

import { Command } from 'commander';
import { runScan } from './cli';

const program = new Command();

program
  .name('agentshield')
  .description('🛡️ Security scanner for AI Agents and MCP Servers')
  .version('0.1.0');

program
  .command('scan')
  .description('Scan a directory for AI agent security vulnerabilities')
  .argument('[path]', 'Target directory to scan', '.')
  .option('-o, --output <file>', 'Output JSON report to file')
  .option('--json', 'Always output JSON report')
  .option('-s, --scanners <names...>', 'Run only specific scanners (prompt, mcp, secret, permission, defense, skill, redteam)')
  .option('-v, --verbose', 'Show detailed progress')
  .option('-e, --exclude <patterns...>', 'Additional glob patterns to exclude (on top of default excludes)')
  .option('-p, --profile <type>', 'Scanner profile: agent (all, default), general (secret+permission+skill), mobile (secret+permission)', 'agent')
  .option('-c, --context <type>', 'Scan context: app (default), framework (framework-aware downgrades), skill (strict, no downgrades)', 'app')
  .action(async (targetPath: string, options) => {
    try {
      const report = await runScan(targetPath, options);
      // Exit with non-zero if critical findings exist
      if (report.summary.critical > 0) {
        process.exit(2);
      }
      if (report.summary.high > 0) {
        process.exit(1);
      }
    } catch (err) {
      console.error('Error:', err);
      process.exit(1);
    }
  });

program.parse();
