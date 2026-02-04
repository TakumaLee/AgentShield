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
];

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
  return findFiles(targetPath, [
    '**/*prompt*',
    '**/*system*',
    '**/*instruction*',
    '**/*.md',
    '**/*.txt',
    '**/*.json',
    '**/*.yaml',
    '**/*.yml',
    '**/*.ts',
    '**/*.js',
    '**/*.py',
  ]);
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
