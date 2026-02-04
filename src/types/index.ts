export type Severity = 'critical' | 'high' | 'medium' | 'info';

/**
 * Scan context controls how findings are severity-adjusted:
 *  - app: default — standard scanning
 *  - framework: framework-aware downgrades for expected patterns
 *  - skill: strict — no downgrades (third-party skill/plugin scanning)
 */
export type ScanContext = 'app' | 'framework' | 'skill';

export interface Finding {
  id: string;
  scanner: string;
  severity: Severity;
  title: string;
  description: string;
  file?: string;
  line?: number;
  recommendation: string;
}

export interface ScanResult {
  scanner: string;
  findings: Finding[];
  scannedFiles: number;
  duration: number; // ms
}

export interface ScanReport {
  version: string;
  timestamp: string;
  target: string;
  results: ScanResult[];
  summary: ReportSummary;
}

export interface ReportSummary {
  totalFindings: number;
  critical: number;
  high: number;
  medium: number;
  info: number;
  grade: string; // A+ ~ F
  score: number; // 0 ~ 100
  scannedFiles: number;
  duration: number;
}

export interface ScannerOptions {
  exclude?: string[];
  context?: ScanContext;
}

export interface ScannerModule {
  name: string;
  description: string;
  scan(targetPath: string, options?: ScannerOptions): Promise<ScanResult>;
}

export interface McpServerConfig {
  mcpServers?: Record<string, McpServerEntry>;
  [key: string]: unknown;
}

export interface McpServerEntry {
  command?: string;
  args?: string[];
  env?: Record<string, string>;
  tools?: McpToolConfig[];
  permissions?: Record<string, unknown>;
  allowlist?: string[];
  denylist?: string[];
  [key: string]: unknown;
}

export interface McpToolConfig {
  name: string;
  description?: string;
  permissions?: string[];
  allowedPaths?: string[];
  blockedPaths?: string[];
  [key: string]: unknown;
}
