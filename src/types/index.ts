export type Severity = 'critical' | 'high' | 'medium' | 'info';

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

export interface ScannerModule {
  name: string;
  description: string;
  scan(targetPath: string): Promise<ScanResult>;
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
