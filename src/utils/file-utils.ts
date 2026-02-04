import * as fs from 'fs';
import * as path from 'path';
import { glob } from 'glob';

export function readFileContent(filePath: string): string {
  return fs.readFileSync(filePath, 'utf-8');
}

export function fileExists(filePath: string): boolean {
  return fs.existsSync(filePath);
}

const DEFAULT_IGNORE = [
  '**/node_modules/**',
  '**/dist/**',
  '**/build/**',
  '**/.git/**',
  '**/.dart_tool/**',
  '**/.flutter-plugins*',
  '**/Pods/**',
  '**/.gradle/**',
  '**/vendor/**',
  '**/__pycache__/**',
  '**/venv/**',
  '**/.venv/**',
  '**/coverage/**',
  '**/*.min.js',
  '**/*.min.css',
  '**/*.map',
  '**/package-lock.json',
  '**/yarn.lock',
  '**/pnpm-lock.yaml',
  '**/*.lock',
  '**/*.freezed.dart',
  '**/*.g.dart',
  '**/*.pb.dart',
  '**/*.mocks.dart',
  '**/ios/Pods/**',
  '**/android/.gradle/**',
  '**/.next/**',
  '**/.nuxt/**',
  '**/.cache/**',
  '**/tmp/**',
  '**/DerivedData/**',
  '**/agentshield-report*.json',
];

/**
 * Merge user-provided exclude patterns with the default ignore list.
 * User patterns are normalized to glob format: "foo" → "**​/foo/**"
 */
export function buildIgnoreList(userExcludes?: string[]): string[] {
  if (!userExcludes || userExcludes.length === 0) return DEFAULT_IGNORE;
  const extra = userExcludes.map(p => {
    // If already a glob pattern, use as-is
    if (p.includes('*') || p.includes('/')) return p;
    // Otherwise, treat as directory name to exclude
    return `**/${p}/**`;
  });
  return [...DEFAULT_IGNORE, ...extra];
}

// Files that are likely test/doc context — findings here get severity downgraded
const TEST_DOC_PATTERNS = [
  /[/\\]tests?[/\\]/i,
  /[/\\]__tests__[/\\]/i,
  /[/\\]spec[/\\]/i,
  /\.test\.[jt]sx?$/i,
  /\.spec\.[jt]sx?$/i,
  /[/\\]test_/i,
  /[/\\]fixtures?[/\\]/i,
  /[/\\]mocks?[/\\]/i,
  /[/\\]cassettes?[/\\]/i,
  /README\.md$/i,
  /CHANGELOG\.md$/i,
  /CONTRIBUTING\.md$/i,
  /[/\\]docs?[/\\]/i,
  /[/\\]examples?[/\\]/i,
];

export function isTestOrDocFile(filePath: string): boolean {
  return TEST_DOC_PATTERNS.some(p => p.test(filePath));
}

// Max file size to scan (256KB) — skip binary/large generated files
const MAX_FILE_SIZE = 256 * 1024;

export async function findFiles(targetPath: string, patterns: string[], excludePatterns?: string[]): Promise<string[]> {
  const results: string[] = [];
  const absTarget = path.resolve(targetPath);
  const ignoreList = buildIgnoreList(excludePatterns);

  for (const pattern of patterns) {
    const files = await glob(pattern, {
      cwd: absTarget,
      absolute: true,
      nodir: true,
      ignore: ignoreList,
    });
    results.push(...files);
  }

  // Deduplicate and filter out oversized files
  const unique = [...new Set(results)];
  return unique.filter(f => {
    try {
      const stat = fs.statSync(f);
      return stat.size <= MAX_FILE_SIZE;
    } catch {
      return false;
    }
  });
}

export async function findConfigFiles(targetPath: string, excludePatterns?: string[]): Promise<string[]> {
  return findFiles(targetPath, [
    '**/*.json',
    '**/*.yaml',
    '**/*.yml',
    '**/.env*',
    '**/config.*',
    '**/mcp*.json',
    '**/mcp*.yaml',
    '**/mcp*.yml',
    '**/claude_desktop_config.json',
  ], excludePatterns);
}

export async function findPromptFiles(targetPath: string, excludePatterns?: string[]): Promise<string[]> {
  // Tier 1: High-signal agent/prompt files (always scan)
  const agentFiles = await findFiles(targetPath, [
    '**/*prompt*',
    '**/*system*',
    '**/*instruction*',
    '**/*agent*',
    '**/*mcp*',
    '**/*tool*',
    '**/SOUL.md',
    '**/AGENTS.md',
    '**/CLAUDE.md',
    '**/claude_desktop_config.json',
    '**/.cursorrules',
    '**/.github/copilot*',
    '**/*config*.json',
    '**/*config*.yaml',
    '**/*config*.yml',
    '**/*settings*.json',
    '**/*settings*.yaml',
    '**/.env*',
  ], excludePatterns);

  // Tier 2: General files but only in small projects (< 200 files)
  // For large projects, only scan agent-specific files
  const allSourceFiles = await findFiles(targetPath, [
    '**/*.md',
    '**/*.txt',
    '**/*.json',
    '**/*.yaml',
    '**/*.yml',
    '**/*.ts',
    '**/*.js',
    '**/*.py',
  ], excludePatterns);

  // If project is large, only use Tier 1 files
  if (allSourceFiles.length > 200) {
    return agentFiles;
  }

  // Small project: scan everything
  return [...new Set([...agentFiles, ...allSourceFiles])];
}

// === Context-aware file classification helpers ===

/**
 * Files whose primary job is managing credentials/tokens/auth.
 * Findings in these files get downgraded in framework context.
 */
const CREDENTIAL_MANAGEMENT_PATTERNS = [
  /[/\\]credentials?\.[jt]sx?$/i,
  /[/\\]tokens?\.[jt]sx?$/i,
  /[/\\]accounts?\.[jt]sx?$/i,
  /[/\\]auth\.[jt]sx?$/i,
  /[/\\]auth-store\.[jt]sx?$/i,
  /[/\\]key-manager\.[jt]sx?$/i,
  /[/\\]secret-manager\.[jt]sx?$/i,
  /[/\\]vault\.[jt]sx?$/i,
];

export function isCredentialManagementFile(filePath: string): boolean {
  return CREDENTIAL_MANAGEMENT_PATTERNS.some(p => p.test(filePath));
}

/**
 * Framework infrastructure directories — path traversal / shell exec
 * is more expected here than in user-facing input code.
 */
const FRAMEWORK_DIR_PATTERNS = [
  /[/\\]src[/\\]/i,
  /[/\\]lib[/\\]/i,
  /[/\\]dist[/\\]/i,
  /[/\\]core[/\\]/i,
  /[/\\]internal[/\\]/i,
  /[/\\]utils[/\\]/i,
  /[/\\]extensions[/\\]/i,
];

export function isFrameworkInfraFile(filePath: string): boolean {
  return FRAMEWORK_DIR_PATTERNS.some(p => p.test(filePath));
}

/**
 * Files that handle user-facing input — findings here stay at original severity.
 */
const USER_INPUT_FILE_PATTERNS = [
  /handler/i,
  /controller/i,
  /route/i,
  /[/\\]api[/\\]/i,
  /endpoint/i,
  /input/i,
  /parse/i,
];

export function isUserInputFile(filePath: string): boolean {
  const basename = filePath.split(/[/\\]/).pop() || '';
  return USER_INPUT_FILE_PATTERNS.some(p => p.test(basename)) ||
    USER_INPUT_FILE_PATTERNS.some(p => p.test(filePath));
}

/**
 * Files inside skill/plugin directories — keep strict severity.
 */
const SKILL_PLUGIN_DIR_PATTERNS = [
  /[/\\]skills?[/\\]/i,
  /[/\\]plugins?[/\\]/i,
  /[/\\]addons?[/\\]/i,
  /[/\\]modules[/\\]/i,
];

export function isSkillPluginFile(filePath: string): boolean {
  return SKILL_PLUGIN_DIR_PATTERNS.some(p => p.test(filePath));
}

/**
 * Check if a project has any auth-related files.
 */
export function hasAuthFiles(files: string[]): boolean {
  const AUTH_FILE_PATTERNS = [
    /[/\\]auth/i,
    /[/\\]credentials?/i,
    /[/\\]pairing/i,
    /[/\\]login/i,
    /[/\\]session/i,
    /[/\\]oauth/i,
  ];
  return files.some(f => AUTH_FILE_PATTERNS.some(p => p.test(f)));
}

export function isJsonFile(filePath: string): boolean {
  return path.extname(filePath).toLowerCase() === '.json';
}

export function isYamlFile(filePath: string): boolean {
  const ext = path.extname(filePath).toLowerCase();
  return ext === '.yaml' || ext === '.yml';
}

export function tryParseJson(content: string): unknown | null {
  try {
    return JSON.parse(content);
  } catch {
    return null;
  }
}
