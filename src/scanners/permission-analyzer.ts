import * as yaml from 'js-yaml';
import { ScannerModule, ScanResult, Finding, ScanContext } from '../types';
import { findConfigFiles, findPromptFiles, readFileContent, isJsonFile, isYamlFile, tryParseJson, isTestOrDocFile, hasAuthFiles, findFiles, isCacheOrDataFile } from '../utils/file-utils';

export const permissionAnalyzer: ScannerModule = {
  name: 'Permission Analyzer',
  description: 'Analyzes agent resource access scope, flags over-privileged configurations, and identifies missing access controls',

  async scan(targetPath: string, options?: { exclude?: string[]; context?: ScanContext }): Promise<ScanResult> {
    const start = Date.now();
    const findings: Finding[] = [];
    const context = options?.context || 'app';
    const configFiles = await findConfigFiles(targetPath, options?.exclude);
    const promptFiles = await findPromptFiles(targetPath, options?.exclude);
    const allFiles = [...new Set([...configFiles, ...promptFiles])];

    // For framework context, check if any auth-related files exist in the project
    let projectHasAuthFiles = false;
    if (context === 'framework') {
      const sourceFiles = await findFiles(targetPath, ['**/*.ts', '**/*.js', '**/*.py'], options?.exclude);
      projectHasAuthFiles = hasAuthFiles([...allFiles, ...sourceFiles]);
    }

    // Skip generic package manifests & dev tool configs — they aren't agent configs
    const SKIP_CONFIG_PATTERNS = [
      /package\.json$/,
      /package-lock\.json$/,
      /tsconfig(\.[^/\\]+)?\.json$/i,
      /pubspec\.yaml$/,
      /Cargo\.toml$/,
      /pyproject\.toml$/,
      /\.eslintrc/,
      /\.prettierrc/,
      /prettier\.config\./,
      /jest\.config/,
      /vitest\.config/,
      /vite\.config/,
      /webpack\.config/,
      /babel\.config/,
      /\.babelrc/,
      /release-please/,
      /renovate/,
      /dependabot/,
      /\.github\//,
      /firebase\.json$/,
      /firestore\.indexes\.json$/,
      /analysis_options\.yaml$/i,
    ];

    for (const file of allFiles) {
      try {
        const content = readFileContent(file);

        // Analyze config files (skip package manifests)
        const isManifest = SKIP_CONFIG_PATTERNS.some(p => p.test(file));
        // Chrome extension / web app manifest.json — not a tool config
        const isWebManifest = /manifest\.json$/i.test(file) && content.includes('"manifest_version"');
        if (!isManifest && !isWebManifest && (isJsonFile(file) || isYamlFile(file))) {
          let parsed: unknown = null;
          if (isJsonFile(file)) parsed = tryParseJson(content);
          else if (isYamlFile(file)) parsed = yaml.load(content);

          if (parsed && typeof parsed === 'object') {
            const obj = parsed as Record<string, unknown>;
            // Only run permission analysis on files that look like tool/MCP configs
            if (isToolOrMcpConfig(obj)) {
              const permFindings = analyzePermissions(obj, file);
              // Downgrade cache/data directory findings to info
              if (isCacheOrDataFile(file)) {
                for (const f of permFindings) {
                  if (f.severity !== 'info') {
                    f.severity = 'info';
                    f.description += ' [cache/data file — severity reduced]';
                  }
                }
              }
              findings.push(...permFindings);
            }
          }
        }

        // Analyze text content for permission-related patterns
        // Only for prompt-like files (.md, .txt), not data/cache files
        if (!isCacheOrDataFile(file)) {
          findings.push(...analyzeTextPermissions(content, file));
        }

        // Analyze tool permission boundaries
        // Only for files that actually define tool permissions, not arbitrary JSON
        if (!isCacheOrDataFile(file)) {
          if (isJsonFile(file) || isYamlFile(file)) {
            // For structured config files, only check if it looks like a tool config
            let parsed: unknown = null;
            try {
              if (isJsonFile(file)) parsed = tryParseJson(content);
              else if (isYamlFile(file)) parsed = yaml.load(content);
            } catch { /* skip */ }
            if (parsed && typeof parsed === 'object' && isToolOrMcpConfig(parsed as Record<string, unknown>)) {
              findings.push(...analyzeToolPermissionBoundaries(content, file));
            }
          } else {
            // For text files (.md, .txt), check if the content is actually defining tool permissions
            // vs just mentioning the word "tool"
            if (isDefiningToolPermissions(content)) {
              findings.push(...analyzeToolPermissionBoundaries(content, file));
            }
          }
        }

        // Downgrade test/doc findings
        // (re-check findings added in this iteration)
      } catch {
        // Skip unreadable files
      }
    }

    // Framework context downgrades
    if (context === 'framework') {
      // Downgrade "No authentication configured" if auth files exist
      if (projectHasAuthFiles) {
        for (const f of findings) {
          if (f.title === 'No authentication configured' && f.severity !== 'info') {
            f.severity = 'info';
            f.description += ' [Authentication modules detected but may not cover all entry points.]';
          }
        }
      }
      // Downgrade tool permission findings — frameworks define tools but permission
      // boundaries are configured by end users, not hardcoded in framework source
      for (const f of findings) {
        if (f.id?.startsWith('PERM-TOOL-UNRESTRICTED') && f.severity === 'critical') {
          f.severity = 'info';
          f.description += ' [Framework context: tool permission boundaries are typically configured by end users, not hardcoded in framework source.]';
        } else if (f.id?.startsWith('PERM-TOOL-PARTIAL') && f.severity === 'high') {
          f.severity = 'info';
          f.description += ' [Framework context: partial boundaries detected in framework code; full configuration is delegated to end users.]';
        }
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

    // Confidence: likely — static analysis of permissions, may have false positives
    for (const f of findings) f.confidence = 'likely';

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

// === Tool Permission Boundary Analysis ===

const ALLOWLIST_PATTERNS = [
  /allowlist/i, /whitelist/i, /allowed[_-]?(?:tools|commands|actions|ops)/i,
  /permitted[_-]?(?:tools|commands|actions|ops)/i,
];

const DENYLIST_PATTERNS = [
  /denylist/i, /blocklist/i, /blacklist/i,
  /blocked[_-]?(?:tools|commands|actions|ops)/i,
  /denied[_-]?(?:tools|commands|actions|ops)/i,
  /restricted[_-]?(?:tools|commands|actions|ops)/i,
];

const CONFIRMATION_PATTERNS = [
  /confirm(?:ation)?[_-]?(?:required|needed|prompt)/i,
  /approve[_-]?(?:before|required|first)/i,
  /dangerous[_-]?(?:ops?|operations?|commands?|tools?)/i,
  /require[_-]?(?:confirmation|approval|consent)/i,
  /human[_-]?(?:in[_-]?the[_-]?loop|approval|review)/i,
  /confirm\s*[:=]\s*true/i,
  /approval\s*[:=]\s*true/i,
];

export function analyzeToolPermissionBoundaries(content: string, filePath?: string): Finding[] {
  const findings: Finding[] = [];

  // Only analyze files that reference tools/skills
  const hasToolRef = /(?:tool|skill|function|command|action|plugin)s?\b/i.test(content);
  if (!hasToolRef) return findings;

  const hasAllowlist = ALLOWLIST_PATTERNS.some(p => p.test(content));
  const hasDenylist = DENYLIST_PATTERNS.some(p => p.test(content));
  const hasConfirmation = CONFIRMATION_PATTERNS.some(p => p.test(content));

  if (!hasAllowlist && !hasDenylist && !hasConfirmation) {
    findings.push({
      id: `PERM-TOOL-UNRESTRICTED-${filePath}`,
      scanner: 'permission-analyzer',
      severity: 'critical',
      title: 'Tools have unrestricted access with no permission boundaries',
      description: 'Tools have unrestricted access with no permission boundaries. Any user could potentially invoke any tool with arbitrary arguments. No allowlist, denylist, or confirmation mechanism detected.',
      file: filePath,
      recommendation: 'Define tool permission boundaries: add allowlists for permitted tools, denylists for dangerous operations, and require confirmation for high-risk tool invocations.',
    });
  } else if (hasAllowlist && hasConfirmation) {
    // Good — has both allowlist AND confirmation for dangerous ops
    // No finding needed
  } else {
    // Partial: has some restrictions but not comprehensive
    const layers: string[] = [];
    if (hasAllowlist) layers.push('allowlist');
    if (hasDenylist) layers.push('denylist');
    if (hasConfirmation) layers.push('confirmation');

    findings.push({
      id: `PERM-TOOL-PARTIAL-${filePath}`,
      scanner: 'permission-analyzer',
      severity: 'high',
      title: 'Tools have partial permission boundaries',
      description: `Tool permission restrictions detected (${layers.join(', ')}) but coverage is incomplete. Consider adding ${!hasAllowlist ? 'allowlist, ' : ''}${!hasDenylist ? 'denylist, ' : ''}${!hasConfirmation ? 'confirmation for dangerous operations, ' : ''}for defense-in-depth.`.replace(/, $/, '.'),
      file: filePath,
      recommendation: 'Strengthen tool permission boundaries: combine allowlists with confirmation prompts for dangerous operations. Apply the principle of least privilege.',
    });
  }

  return findings;
}

// === Config Structure Detection ===

/**
 * Keys that indicate a JSON/YAML file is a tool/MCP/agent config,
 * not just arbitrary data (cache, knowledge, logs, etc.)
 */
const TOOL_CONFIG_KEYS = [
  'mcpServers', 'mcp_servers', 'servers',
  'tools', 'tool', 'toolConfig',
  'permissions', 'allowlist', 'denylist', 'blocklist',
  'command', 'args', 'env',
  'allowedPaths', 'rootDir', 'sandboxPath',
  'endpoint', 'api', 'apiKey',
  'functions', 'function_call',
  'plugins', 'skills',
  'agent', 'agents',
  'model', 'provider',
];

/**
 * Check if a parsed JSON/YAML object looks like a tool/MCP/agent config.
 * Returns true only if the object contains at least one tool/server-related key.
 */
export function isToolOrMcpConfig(obj: Record<string, unknown>): boolean {
  const keys = getAllKeys(obj);
  return TOOL_CONFIG_KEYS.some(k => keys.has(k.toLowerCase()));
}

function getAllKeys(obj: Record<string, unknown>, depth = 0, maxDepth = 3): Set<string> {
  const keys = new Set<string>();
  if (depth > maxDepth) return keys;
  for (const [key, value] of Object.entries(obj)) {
    keys.add(key.toLowerCase());
    if (value && typeof value === 'object' && !Array.isArray(value)) {
      const childKeys = getAllKeys(value as Record<string, unknown>, depth + 1, maxDepth);
      for (const ck of childKeys) keys.add(ck);
    }
  }
  return keys;
}

/**
 * Check if text content is actually defining tool permissions (not just mentioning "tool").
 * For .md/.txt files, we need stronger signals than just the word "tool".
 */
export function isDefiningToolPermissions(content: string): boolean {
  // Must have both: (1) tool-related keywords AND (2) permission-related keywords
  const hasToolDefinition = /(?:allowed[_-]?tools|tool[_-]?(?:permissions?|config|settings|access)|define\s+tools|register\s+tools|available\s+tools)/i.test(content);
  const hasPermissionConfig = /(?:allowlist|denylist|blocklist|whitelist|blacklist|permission|restrict|confirm|approve|boundary|boundaries)/i.test(content);
  return hasToolDefinition || (hasPermissionConfig && /\btool/i.test(content));
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
