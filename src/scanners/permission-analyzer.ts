import * as yaml from 'js-yaml';
import { ScannerModule, ScanResult, Finding } from '../types';
import { findConfigFiles, findPromptFiles, readFileContent, isJsonFile, isYamlFile, tryParseJson, isTestOrDocFile } from '../utils/file-utils';

export const permissionAnalyzer: ScannerModule = {
  name: 'Permission Analyzer',
  description: 'Analyzes agent resource access scope, flags over-privileged configurations, and identifies missing access controls',

  async scan(targetPath: string): Promise<ScanResult> {
    const start = Date.now();
    const findings: Finding[] = [];
    const configFiles = await findConfigFiles(targetPath);
    const promptFiles = await findPromptFiles(targetPath);
    const allFiles = [...new Set([...configFiles, ...promptFiles])];

    // Skip generic package manifests — they aren't agent configs
    const SKIP_CONFIG_PATTERNS = [
      /package\.json$/,
      /tsconfig\.json$/,
      /pubspec\.yaml$/,
      /Cargo\.toml$/,
      /pyproject\.toml$/,
      /\.eslintrc/,
      /\.prettierrc/,
      /jest\.config/,
      /vite\.config/,
      /webpack\.config/,
    ];

    for (const file of allFiles) {
      try {
        const content = readFileContent(file);

        // Analyze config files (skip package manifests)
        const isManifest = SKIP_CONFIG_PATTERNS.some(p => p.test(file));
        if (!isManifest && (isJsonFile(file) || isYamlFile(file))) {
          let parsed: unknown = null;
          if (isJsonFile(file)) parsed = tryParseJson(content);
          else if (isYamlFile(file)) parsed = yaml.load(content);

          if (parsed && typeof parsed === 'object') {
            findings.push(...analyzePermissions(parsed as Record<string, unknown>, file));
          }
        }

        // Analyze text content for permission-related patterns
        findings.push(...analyzeTextPermissions(content, file));

        // Downgrade test/doc findings
        // (re-check findings added in this iteration)
      } catch {
        // Skip unreadable files
      }
    }

    // Downgrade all test/doc findings
    for (const f of findings) {
      if (f.file && isTestOrDocFile(f.file)) {
        if (f.severity === 'critical') f.severity = 'medium';
        else if (f.severity === 'high') f.severity = 'info';
        if (!f.description.includes('[test/doc file')) {
          f.description += ' [test/doc file — severity reduced]';
        }
      }
    }

    return {
      scanner: 'Permission Analyzer',
      findings,
      scannedFiles: allFiles.length,
      duration: Date.now() - start,
    };
  },
};

export function analyzePermissions(config: Record<string, unknown>, filePath?: string): Finding[] {
  const findings: Finding[] = [];
  const configStr = JSON.stringify(config).toLowerCase();

  // Check for wildcard permissions
  findings.push(...checkWildcardAccess(config, filePath));

  // Check for unrestricted network access
  findings.push(...checkNetworkAccess(config, filePath));

  // Check for filesystem scope
  findings.push(...checkFilesystemScope(config, filePath));

  // Check for missing rate limits
  if (configStr.includes('tool') || configStr.includes('function') || configStr.includes('api')) {
    if (!configStr.includes('rate') && !configStr.includes('limit') && !configStr.includes('throttle') && !configStr.includes('quota')) {
      findings.push({
        id: `PERM-NORATE-${filePath}`,
        scanner: 'permission-analyzer',
        severity: 'medium',
        title: 'No rate limiting configured',
        description: 'The configuration defines tools/APIs but no rate limiting, throttling, or quota settings were found.',
        file: filePath,
        recommendation: 'Add rate limiting to prevent abuse. Configure per-tool or global request limits.',
      });
    }
  }

  // Check for missing auth configuration
  if (configStr.includes('server') || configStr.includes('endpoint') || configStr.includes('api')) {
    if (!configStr.includes('auth') && !configStr.includes('token') && !configStr.includes('key') && !configStr.includes('credential')) {
      findings.push({
        id: `PERM-NOAUTH-${filePath}`,
        scanner: 'permission-analyzer',
        severity: 'high',
        title: 'No authentication configured',
        description: 'Server/API configuration found without apparent authentication settings.',
        file: filePath,
        recommendation: 'Add authentication configuration (API keys, tokens, or OAuth) to protect endpoints.',
      });
    }
  }

  // Check for missing logging/audit
  if (!configStr.includes('log') && !configStr.includes('audit') && !configStr.includes('monitor')) {
    if (configStr.includes('tool') || configStr.includes('server')) {
      findings.push({
        id: `PERM-NOLOG-${filePath}`,
        scanner: 'permission-analyzer',
        severity: 'info',
        title: 'No logging/audit configuration detected',
        description: 'No logging, auditing, or monitoring settings found in the configuration.',
        file: filePath,
        recommendation: 'Enable logging for all tool invocations. Audit logs are essential for security monitoring.',
      });
    }
  }

  return findings;
}

function checkWildcardAccess(config: Record<string, unknown>, filePath?: string): Finding[] {
  const findings: Finding[] = [];
  const configStr = JSON.stringify(config);

  // Check for wildcard patterns in permissions
  const wildcardPatterns = [
    { pattern: /"permissions"\s*:\s*\["?\*"?\]/, desc: 'Wildcard permission (*)' },
    { pattern: /"access"\s*:\s*"?(all|full|unrestricted)"?/i, desc: 'Unrestricted access' },
    { pattern: /"scope"\s*:\s*"?(all|full|\*)"?/i, desc: 'Full scope access' },
    { pattern: /"allowedPaths"\s*:\s*\["?\/?"?\]/, desc: 'Root path in allowedPaths' },
    { pattern: /"allowedPaths"\s*:\s*\["?\*"?\]/, desc: 'Wildcard in allowedPaths' },
  ];

  for (const wp of wildcardPatterns) {
    if (wp.pattern.test(configStr)) {
      findings.push({
        id: `PERM-WILD-${wp.desc.replace(/\s+/g, '-')}-${filePath}`,
        scanner: 'permission-analyzer',
        severity: 'critical',
        title: `Over-privileged: ${wp.desc}`,
        description: `Configuration contains ${wp.desc.toLowerCase()} which grants broader access than typically necessary.`,
        file: filePath,
        recommendation: 'Replace wildcard permissions with specific, minimal permissions following the principle of least privilege.',
      });
    }
  }

  return findings;
}

function checkNetworkAccess(config: Record<string, unknown>, filePath?: string): Finding[] {
  const findings: Finding[] = [];
  const configStr = JSON.stringify(config);

  // Check for unrestricted external API access
  if (/"url"\s*:\s*"https?:\/\//.test(configStr) || /"endpoint"\s*:\s*"https?:\/\//.test(configStr)) {
    if (!/"allowedDomains"/.test(configStr) && !/"denyDomains"/.test(configStr) &&
        !/"allowedUrls"/.test(configStr) && !/"blockedUrls"/.test(configStr)) {
      findings.push({
        id: `PERM-NETOPEN-${filePath}`,
        scanner: 'permission-analyzer',
        severity: 'high',
        title: 'External API access without domain restrictions',
        description: 'Configuration includes external URLs but no domain allowlist/denylist is configured.',
        file: filePath,
        recommendation: 'Add domain allowlist to restrict which external services can be accessed.',
      });
    }
  }

  return findings;
}

function checkFilesystemScope(config: Record<string, unknown>, filePath?: string): Finding[] {
  const findings: Finding[] = [];
  const configStr = JSON.stringify(config);

  // Detect filesystem tools with broad scope
  const fsPatterns = [
    { pattern: /"command"\s*:\s*"[^"]*filesystem[^"]*"/i, tool: 'filesystem' },
    { pattern: /"name"\s*:\s*"[^"]*(?:read|write|delete)_file[^"]*"/i, tool: 'file operations' },
    { pattern: /"name"\s*:\s*"[^"]*(?:read|write)_dir[^"]*"/i, tool: 'directory operations' },
  ];

  for (const fsp of fsPatterns) {
    if (fsp.pattern.test(configStr)) {
      // Check if paths are scoped
      if (!/"allowedPaths"/.test(configStr) && !/"rootDir"/.test(configStr) &&
          !/"sandboxPath"/.test(configStr) && !/"workDir"/.test(configStr)) {
        findings.push({
          id: `PERM-FS-${fsp.tool.replace(/\s+/g, '-')}-${filePath}`,
          scanner: 'permission-analyzer',
          severity: 'high',
          title: `${fsp.tool} tool without path scoping`,
          description: `${fsp.tool} capabilities detected without path restrictions, potentially allowing access to the entire filesystem.`,
          file: filePath,
          recommendation: `Configure allowedPaths or rootDir to restrict ${fsp.tool} access to necessary directories only.`,
        });
      }
    }
  }

  return findings;
}

export function analyzeTextPermissions(content: string, filePath?: string): Finding[] {
  const findings: Finding[] = [];
  const lines = content.split('\n');

  const dangerousGrants = [
    { pattern: /you\s+(can|have|are\s+allowed\s+to)\s+(access|read|write|delete|modify)\s+(any|all|every)\s+(file|directory|folder|path)/i, desc: 'Unrestricted file access grant in prompt' },
    { pattern: /full\s+access\s+to\s+(the\s+)?(system|filesystem|network|internet|database)/i, desc: 'Full system access grant in prompt' },
    { pattern: /no\s+restrictions?\s+on\s+(what|which|where)\s+you\s+can/i, desc: 'Explicit no-restriction statement in prompt' },
    { pattern: /you\s+(may|can)\s+execute\s+any\s+(command|code|script)/i, desc: 'Unrestricted code execution grant' },
    { pattern: /access\s+to\s+all\s+(user|customer|private)\s+data/i, desc: 'Unrestricted PII/data access grant' },
  ];

  for (let i = 0; i < lines.length; i++) {
    for (const dg of dangerousGrants) {
      if (dg.pattern.test(lines[i])) {
        findings.push({
          id: `PERM-TEXT-${dg.desc.replace(/\s+/g, '-').substring(0, 40)}-${filePath}-${i + 1}`,
          scanner: 'permission-analyzer',
          severity: 'high',
          title: dg.desc,
          description: `Line ${i + 1}: "${lines[i].trim().substring(0, 120)}"`,
          file: filePath,
          line: i + 1,
          recommendation: 'Apply the principle of least privilege. Grant only the specific permissions needed for each task.',
        });
      }
    }
  }

  return findings;
}
