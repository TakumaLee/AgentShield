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
  '**/agentshield-report*.json',
];

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

export async function findFiles(targetPath: string, patterns: string[]): Promise<string[]> {
  const results: string[] = [];
  const absTarget = path.resolve(targetPath);

  for (const pattern of patterns) {
    const files = await glob(pattern, {
      cwd: absTarget,
      absolute: true,
      nodir: true,
      ignore: DEFAULT_IGNORE,
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

export async function findConfigFiles(targetPath: string): Promise<string[]> {
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
  ]);
}

export async function findPromptFiles(targetPath: string): Promise<string[]> {
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
  ]);

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
  ]);

  // If project is large, only use Tier 1 files
  if (allSourceFiles.length > 200) {
    return agentFiles;
  }

  // Small project: scan everything
  return [...new Set([...agentFiles, ...allSourceFiles])];
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
