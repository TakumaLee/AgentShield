import * as yaml from 'js-yaml';
import { ScannerModule, ScanResult, Finding, McpServerConfig, McpServerEntry } from '../types';
import { findConfigFiles, readFileContent, isJsonFile, isYamlFile, tryParseJson } from '../utils/file-utils';
import { DANGEROUS_TOOLS, DANGEROUS_PERMISSIONS } from '../patterns/injection-patterns';

export const mcpConfigAuditor: ScannerModule = {
  name: 'MCP Config Auditor',
  description: 'Audits MCP server configuration files for overly permissive tools, missing access controls, and insecure settings',

  async scan(targetPath: string, options?: { exclude?: string[] }): Promise<ScanResult> {
    const start = Date.now();
    const findings: Finding[] = [];
    const files = await findConfigFiles(targetPath, options?.exclude);

    // Skip package manifests and non-agent config files
    const SKIP_PATTERNS = [
      /package\.json$/,
      /tsconfig\.json$/,
      /pubspec\.yaml$/,
      /\.eslintrc/,
      /jest\.config/,
      /release-please/,
      /renovate/,
      /dependabot/,
    ];

    for (const file of files) {
      if (SKIP_PATTERNS.some(p => p.test(file))) continue;

      try {
        const content = readFileContent(file);
        let parsed: unknown = null;

        if (isJsonFile(file)) {
          parsed = tryParseJson(content);
        } else if (isYamlFile(file)) {
          parsed = yaml.load(content);
        }

        if (parsed && typeof parsed === 'object') {
          const fileFindings = auditConfig(parsed as Record<string, unknown>, file);
          findings.push(...fileFindings);
        }
      } catch {
        // Skip unreadable/unparseable files
      }
    }

    // Confidence: definite — config-based findings are concrete
    for (const f of findings) f.confidence = 'definite';

    return {
      scanner: 'MCP Config Auditor',
      findings,
      scannedFiles: files.length,
      duration: Date.now() - start,
    };
  },
};

export function auditConfig(config: Record<string, unknown>, filePath?: string): Finding[] {
  const findings: Finding[] = [];

  // Check if this looks like an MCP config
  const mcpServers = (config.mcpServers || config.mcp_servers || config.servers) as Record<string, McpServerEntry> | undefined;

  if (mcpServers && typeof mcpServers === 'object') {
    for (const [serverName, serverConfig] of Object.entries(mcpServers)) {
      findings.push(...auditServer(serverName, serverConfig, filePath));
    }
  }

  // Also check top-level for tool configs
  if (config.tools && Array.isArray(config.tools)) {
    findings.push(...auditTools(config.tools, filePath));
  }

  // Check for environment variable exposure
  findings.push(...auditEnvVars(config, filePath));

  return findings;
}

function auditServer(name: string, server: McpServerEntry, filePath?: string): Finding[] {
  const findings: Finding[] = [];

  // Check command for dangerous executables
  if (server.command) {
    const dangerousCmds = ['bash', 'cmd', 'powershell', 'python', 'node', '/bin/sh', '/bin/zsh'];
    for (const cmd of dangerousCmds) {
      if (server.command === cmd || server.command.endsWith('/' + cmd)) {
        findings.push({
          id: `MCP-CMD-${name}`,
          scanner: 'mcp-config-auditor',
          severity: 'high',
          title: `Server "${name}" uses potentially dangerous command: ${cmd}`,
          description: `The MCP server "${name}" is configured to run "${server.command}" which could allow arbitrary code execution.`,
          file: filePath,
          recommendation: 'Use specific executables instead of shell interpreters. Restrict the command to the minimum required functionality.',
        });
      }
    }
  }

  // Check args for dangerous flags
  if (server.args && Array.isArray(server.args)) {
    for (const arg of server.args) {
      if (typeof arg === 'string' && (arg.includes('--allow-all') || arg.includes('--no-restrict') || arg.includes('--unsafe'))) {
        findings.push({
          id: `MCP-ARG-${name}-${arg}`,
          scanner: 'mcp-config-auditor',
          severity: 'critical',
          title: `Server "${name}" has unsafe argument: ${arg}`,
          description: `The argument "${arg}" disables security restrictions on server "${name}".`,
          file: filePath,
          recommendation: 'Remove unsafe flags and configure specific permissions instead.',
        });
      }
    }

    // Check for wildcard paths
    for (const arg of server.args) {
      if (typeof arg === 'string' && (arg === '/' || arg === '/*' || arg === '/**' || arg === '*' || arg === 'C:\\')) {
        findings.push({
          id: `MCP-WILDCARD-${name}`,
          scanner: 'mcp-config-auditor',
          severity: 'critical',
          title: `Server "${name}" has wildcard/root path access`,
          description: `The server "${name}" is configured with path "${arg}" which grants access to the entire filesystem.`,
          file: filePath,
          recommendation: 'Restrict path access to specific directories needed by the tool.',
        });
      }
    }
  }

  // Check for missing allowlist/denylist
  if (!server.allowlist && !server.denylist && !server.blockedPaths && !server.allowedPaths) {
    const hasTools = server.tools && Array.isArray(server.tools) && server.tools.length > 0;
    if (hasTools || server.command) {
      findings.push({
        id: `MCP-NOLIST-${name}`,
        scanner: 'mcp-config-auditor',
        severity: 'medium',
        title: `Server "${name}" lacks allowlist/denylist`,
        description: `The server "${name}" has no explicit allowlist or denylist configured, meaning all operations may be permitted by default.`,
        file: filePath,
        recommendation: 'Add allowlist or denylist configuration to restrict permitted operations.',
      });
    }
  }

  // Check env vars for leaked secrets
  if (server.env && typeof server.env === 'object') {
    for (const [key, value] of Object.entries(server.env)) {
      if (typeof value === 'string' && !value.startsWith('${') && !value.startsWith('$')) {
        const secretPatterns = ['key', 'secret', 'token', 'password', 'passwd', 'credential'];
        if (secretPatterns.some(p => key.toLowerCase().includes(p))) {
          findings.push({
            id: `MCP-ENV-${name}-${key}`,
            scanner: 'mcp-config-auditor',
            severity: 'critical',
            title: `Server "${name}" has hardcoded secret in env: ${key}`,
            description: `The environment variable "${key}" appears to contain a hardcoded secret value instead of a reference to a secret store.`,
            file: filePath,
            recommendation: 'Use environment variable references (${VAR}) or a secret manager instead of hardcoded values.',
          });
        }
      }
    }
  }

  // Check tools for dangerous permissions
  if (server.tools && Array.isArray(server.tools)) {
    findings.push(...auditTools(server.tools, filePath, name));
  }

  return findings;
}

function auditTools(tools: unknown[], filePath?: string, serverName?: string): Finding[] {
  const findings: Finding[] = [];
  const prefix = serverName ? `Server "${serverName}" → ` : '';

  for (const tool of tools) {
    if (typeof tool !== 'object' || tool === null) continue;
    const t = tool as Record<string, unknown>;
    const toolName = (t.name as string) || 'unknown';

    // Check if tool name matches dangerous patterns
    for (const dangerous of DANGEROUS_TOOLS) {
      if (toolName.toLowerCase().includes(dangerous)) {
        findings.push({
          id: `MCP-TOOL-${serverName || 'root'}-${toolName}`,
          scanner: 'mcp-config-auditor',
          severity: 'high',
          title: `${prefix}Dangerous tool detected: ${toolName}`,
          description: `The tool "${toolName}" matches dangerous pattern "${dangerous}" and may allow unrestricted system access.`,
          file: filePath,
          recommendation: `Review if tool "${toolName}" is necessary. If so, add strict input validation and scope restrictions.`,
        });
        break;
      }
    }

    // Check permissions
    if (t.permissions && Array.isArray(t.permissions)) {
      for (const perm of t.permissions) {
        if (typeof perm === 'string' && DANGEROUS_PERMISSIONS.includes(perm)) {
          findings.push({
            id: `MCP-PERM-${serverName || 'root'}-${toolName}-${perm}`,
            scanner: 'mcp-config-auditor',
            severity: 'critical',
            title: `${prefix}Tool "${toolName}" has dangerous permission: ${perm}`,
            description: `The permission "${perm}" on tool "${toolName}" grants overly broad access.`,
            file: filePath,
            recommendation: 'Replace wildcard/admin permissions with specific, scoped permissions.',
          });
        }
      }
    }
  }

  return findings;
}

function auditEnvVars(config: Record<string, unknown>, filePath?: string): Finding[] {
  const findings: Finding[] = [];

  // Recursively search for env-like patterns
  const json = JSON.stringify(config);

  // Check for URLs with credentials
  const urlWithCreds = /https?:\/\/[^:]+:[^@]+@/g;
  if (urlWithCreds.test(json)) {
    findings.push({
      id: `MCP-URL-CREDS`,
      scanner: 'mcp-config-auditor',
      severity: 'critical',
      title: 'URL with embedded credentials detected',
      description: 'A URL containing embedded username:password credentials was found in the configuration.',
      file: filePath,
      recommendation: 'Remove credentials from URLs. Use environment variables or a secret manager.',
    });
  }

  return findings;
}
