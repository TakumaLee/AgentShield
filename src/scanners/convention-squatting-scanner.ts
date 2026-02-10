import * as fs from 'fs';
import * as path from 'path';
import * as dns from 'dns';
import { Scanner, ScanResult, Finding, Severity } from '../types';
import { walkFiles, FileEntry } from '../utils/file-walker';

// --- Constants ---

/** TLDs that collide with common file extensions. */
export const RISKY_TLDS = new Set([
  '.md', '.ai', '.io', '.sh', '.py', '.rs', '.ts', '.js', '.app', '.dev',
]);

/** Well-known agent convention filenames that are squattable domains. */
export const KNOWN_CONVENTION_FILES: string[] = [
  'heartbeat.md', 'readme.md', 'agents.md', 'soul.md', 'memory.md',
  'bootstrap.md', 'identity.md', 'tools.md',
];

/** Files commonly read on a periodic/heartbeat schedule. */
const HEARTBEAT_FILENAMES = new Set([
  'heartbeat.md', 'heartbeat.json', 'heartbeat.yaml', 'heartbeat.yml',
]);

/** Patterns indicating URL-based file resolution. */
const URL_RESOLUTION_PATTERNS: Array<{ pattern: RegExp; desc: string }> = [
  { pattern: /\bhttp\.get\s*\(\s*['"`]?[\w-]+\.\w{2,4}['"`]?\s*\)/gi, desc: 'http.get with filename-like argument' },
  { pattern: /\bfetch\s*\(\s*['"`][\w-]+\.\w{2,4}['"`]\s*\)/gi, desc: 'fetch() with bare filename argument' },
  { pattern: /\baxios\s*\.\s*get\s*\(\s*['"`][\w-]+\.\w{2,4}['"`]\s*\)/gi, desc: 'axios.get with filename-like argument' },
  { pattern: /\burllib\.request\.urlopen\s*\(\s*['"`][\w-]+\.\w{2,4}['"`]\s*\)/gi, desc: 'urllib with filename-like argument' },
  { pattern: /\brequests\.get\s*\(\s*['"`][\w-]+\.\w{2,4}['"`]\s*\)/gi, desc: 'requests.get with filename-like argument' },
  { pattern: /\bnew\s+URL\s*\(\s*['"`][\w-]+\.\w{2,4}['"`]\s*\)/gi, desc: 'new URL() with filename-like argument' },
];

// --- Helpers ---

function findLineNumber(content: string, matchIndex: number): number {
  return content.substring(0, matchIndex).split('\n').length;
}

/**
 * Check if a filename (e.g. "README.md") could be interpreted as a valid
 * domain by checking its extension against risky TLDs.
 */
export function isTLDCollision(filename: string): boolean {
  const ext = path.extname(filename).toLowerCase();
  return RISKY_TLDS.has(ext);
}

/**
 * Resolve a domain via DNS. Returns true if any A/AAAA record exists.
 * Wrapped for testability – callers can override via the resolver param.
 */
export async function domainResolves(
  domain: string,
  resolver: (hostname: string) => Promise<string[]> = defaultResolve,
): Promise<boolean> {
  try {
    const addrs = await resolver(domain);
    return addrs.length > 0;
  } catch {
    return false;
  }
}

function defaultResolve(hostname: string): Promise<string[]> {
  return dns.promises.resolve4(hostname);
}

// --- Scanner ---

export class ConventionSquattingScanner implements Scanner {
  name = 'ConventionSquattingScanner';
  description =
    'Detects convention filenames that collide with registrable domain TLDs (.md, .ai, .io, etc.) and URL resolution risks';

  /** Injected resolver for testing. */
  private resolver: (hostname: string) => Promise<string[]>;
  /** Whether to perform live DNS checks. */
  private dnsCheck: boolean;

  constructor(opts?: { resolver?: (hostname: string) => Promise<string[]>; dnsCheck?: boolean }) {
    this.resolver = opts?.resolver ?? defaultResolve;
    this.dnsCheck = opts?.dnsCheck ?? false;
  }

  async scan(targetDir: string): Promise<ScanResult> {
    const start = Date.now();
    const files = walkFiles(targetDir);
    const findings: Finding[] = [];

    // Rule 1: Convention Filename TLD Collision
    for (const file of files) {
      const basename = path.basename(file.relativePath);
      if (isTLDCollision(basename)) {
        const domain = basename.toLowerCase();
        const isKnown = KNOWN_CONVENTION_FILES.includes(domain);
        const isHeartbeat = HEARTBEAT_FILENAMES.has(domain);

        const severity: Severity = isHeartbeat ? 'HIGH' : isKnown ? 'MEDIUM' : 'LOW';
        const rec = isHeartbeat
          ? 'CRITICAL: This file is read periodically — a squatted domain would enable persistent injection. Use absolute local paths and validate file source is local filesystem, not network.'
          : 'Filename resolves as a valid domain. Ensure agent reads via local fs path, not URL resolution. Add integrity checks (hash verification) for convention files.';

        findings.push({
          scanner: this.name,
          rule: 'SQUAT-001',
          severity,
          file: file.relativePath,
          line: 0,
          message: `Convention filename "${basename}" is a registrable domain (TLD collision: ${path.extname(basename)})`,
          evidence: `${domain} — ${rec}`,
        });

        // Rule 4: Heartbeat/Periodic Read Risk (additional finding)
        if (isHeartbeat) {
          findings.push({
            scanner: this.name,
            rule: 'SQUAT-004',
            severity: 'HIGH',
            file: file.relativePath,
            line: 0,
            message: `Heartbeat file "${basename}" is highest risk for persistent injection via domain squatting`,
            evidence:
              'Files read periodically can be hijacked if resolved via URL. Use absolute local path, verify file hash, ensure fs-only access.',
          });
        }
      }
    }

    // Rule 2: URL Resolution Risk
    for (const file of files) {
      for (const { pattern, desc } of URL_RESOLUTION_PATTERNS) {
        const regex = new RegExp(pattern.source, pattern.flags);
        let match: RegExpExecArray | null;
        while ((match = regex.exec(file.content)) !== null) {
          findings.push({
            scanner: this.name,
            rule: 'SQUAT-002',
            severity: 'HIGH',
            file: file.relativePath,
            line: findLineNumber(file.content, match.index),
            message: `URL resolution risk: ${desc}`,
            evidence: `${match[0].substring(0, 120)} — Recommendation: Use fs.readFileSync or equivalent for local files. Never pass bare filenames to network APIs.`,
          });
        }
      }
    }

    // Rule 3: Known Squatted Domains (DNS check)
    if (this.dnsCheck) {
      for (const domain of KNOWN_CONVENTION_FILES) {
        const resolves = await domainResolves(domain, this.resolver);
        if (resolves) {
          findings.push({
            scanner: this.name,
            rule: 'SQUAT-003',
            severity: 'CRITICAL',
            file: '<dns-check>',
            line: 0,
            message: `Known convention filename "${domain}" resolves as a live domain`,
            evidence: `${domain} has DNS A records. An attacker (or opportunist) has registered this domain. Any agent resolving this filename via URL will fetch attacker-controlled content.`,
          });
        }
      }
    }

    return {
      scanner: this.name,
      findings,
      filesScanned: files.length,
      duration: Date.now() - start,
    };
  }
}
