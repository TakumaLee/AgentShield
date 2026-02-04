import * as fs from 'fs';
import * as path from 'path';
import { findFiles, findPromptFiles, findConfigFiles, buildIgnoreList } from '../src/utils/file-utils';
import { filterScannersByProfile, ProfileType } from '../src/cli';
import { promptInjectionTester } from '../src/scanners/prompt-injection-tester';
import { mcpConfigAuditor } from '../src/scanners/mcp-config-auditor';
import { secretLeakScanner } from '../src/scanners/secret-leak-scanner';
import { permissionAnalyzer } from '../src/scanners/permission-analyzer';
import { defenseAnalyzer } from '../src/scanners/defense-analyzer';
import { skillAuditor } from '../src/scanners/skill-auditor';
import { redTeamSimulator } from '../src/scanners/red-team-simulator';
import { ScannerModule } from '../src/types';

const TEMP_DIR = path.join(__dirname, '__temp_exclude_profile__');

const ALL_SCANNERS: ScannerModule[] = [
  promptInjectionTester,
  mcpConfigAuditor,
  secretLeakScanner,
  permissionAnalyzer,
  defenseAnalyzer,
  skillAuditor,
  redTeamSimulator,
];

beforeAll(() => {
  fs.mkdirSync(TEMP_DIR, { recursive: true });
});

afterAll(() => {
  fs.rmSync(TEMP_DIR, { recursive: true, force: true });
});

// ========== buildIgnoreList ==========
describe('buildIgnoreList', () => {
  test('returns default list when no user excludes', () => {
    const list = buildIgnoreList();
    expect(list).toContain('**/node_modules/**');
    expect(list).toContain('**/.git/**');
    expect(list).toContain('**/DerivedData/**');
  });

  test('returns default list for empty array', () => {
    const list = buildIgnoreList([]);
    expect(list).toContain('**/node_modules/**');
  });

  test('appends user patterns as glob format', () => {
    const list = buildIgnoreList(['vendor-custom', 'tmp-data']);
    expect(list).toContain('**/vendor-custom/**');
    expect(list).toContain('**/tmp-data/**');
    // Still has defaults
    expect(list).toContain('**/node_modules/**');
  });

  test('keeps glob patterns as-is', () => {
    const list = buildIgnoreList(['**/*.log', 'src/generated/**']);
    expect(list).toContain('**/*.log');
    expect(list).toContain('src/generated/**');
  });
});

// ========== --exclude functionality ==========
describe('--exclude file filtering', () => {
  const excludeDir = path.join(TEMP_DIR, 'exclude-test');

  beforeAll(() => {
    // Create directory structure:
    // exclude-test/
    //   prompt.md (should be found)
    //   custom-vendor/prompt.md (should be excluded with --exclude)
    //   node_modules/prompt.md (always excluded by default)
    fs.mkdirSync(path.join(excludeDir, 'custom-vendor'), { recursive: true });
    fs.mkdirSync(path.join(excludeDir, 'node_modules'), { recursive: true });
    fs.writeFileSync(path.join(excludeDir, 'prompt.md'), 'You are a helpful assistant.');
    fs.writeFileSync(path.join(excludeDir, 'custom-vendor', 'prompt.md'), 'Vendor prompt');
    fs.writeFileSync(path.join(excludeDir, 'node_modules', 'prompt.md'), 'Node modules prompt');
  });

  test('default excludes skip node_modules', async () => {
    const files = await findPromptFiles(excludeDir);
    const nodeModFile = files.find(f => f.includes('node_modules'));
    expect(nodeModFile).toBeUndefined();
  });

  test('custom exclude skips additional directories', async () => {
    const files = await findPromptFiles(excludeDir, ['custom-vendor']);
    const vendorFile = files.find(f => f.includes('custom-vendor'));
    expect(vendorFile).toBeUndefined();
    // Root prompt.md should still be found
    const rootPrompt = files.find(f => f.endsWith('prompt.md') && !f.includes('custom-vendor'));
    expect(rootPrompt).toBeDefined();
  });

  test('findFiles respects exclude patterns', async () => {
    const files = await findFiles(excludeDir, ['**/*.md'], ['custom-vendor']);
    const vendorFile = files.find(f => f.includes('custom-vendor'));
    expect(vendorFile).toBeUndefined();
    expect(files.length).toBeGreaterThan(0);
  });

  test('findConfigFiles respects exclude patterns', async () => {
    // Create a config in a custom dir
    const configDir = path.join(excludeDir, 'my-configs');
    fs.mkdirSync(configDir, { recursive: true });
    fs.writeFileSync(path.join(configDir, 'config.json'), '{"key": "value"}');
    fs.writeFileSync(path.join(excludeDir, 'config.json'), '{"key": "value"}');

    const files = await findConfigFiles(excludeDir, ['my-configs']);
    const excludedFile = files.find(f => f.includes('my-configs'));
    expect(excludedFile).toBeUndefined();
    // Root config should be found
    const rootConfig = files.find(f => f.endsWith('config.json') && !f.includes('my-configs'));
    expect(rootConfig).toBeDefined();
  });

  test('scanner scan() respects exclude option', async () => {
    // Create a dir with a secret in an excluded subdir
    const scanDir = path.join(TEMP_DIR, 'scanner-exclude');
    const excludedSubDir = path.join(scanDir, 'generated-code');
    fs.mkdirSync(excludedSubDir, { recursive: true });
    fs.writeFileSync(path.join(excludedSubDir, 'config.json'), JSON.stringify({
      apiKey: 'sk-abcdefghijklmnopqrstuvwxyz1234567890',
    }));
    // Also put a clean file at root so scanner has something to scan
    fs.writeFileSync(path.join(scanDir, 'prompt.md'), 'You are a helpful assistant.');

    const resultWithExclude = await secretLeakScanner.scan(scanDir, { exclude: ['generated-code'] });
    const findingsInExcluded = resultWithExclude.findings.filter(f =>
      f.file && f.file.includes('generated-code')
    );
    expect(findingsInExcluded.length).toBe(0);
  });
});

// ========== Default excludes always apply ==========
describe('default excludes always apply', () => {
  test('node_modules is always excluded even without --exclude', async () => {
    const dir = path.join(TEMP_DIR, 'default-exclude');
    fs.mkdirSync(path.join(dir, 'node_modules'), { recursive: true });
    fs.writeFileSync(path.join(dir, 'node_modules', 'agent.js'), 'const x = 1;');
    fs.writeFileSync(path.join(dir, 'agent.js'), 'const y = 2;');

    const files = await findFiles(dir, ['**/*.js']);
    expect(files.some(f => f.includes('node_modules'))).toBe(false);
    expect(files.length).toBe(1);
  });

  test('.git is always excluded', async () => {
    const dir = path.join(TEMP_DIR, 'git-exclude');
    fs.mkdirSync(path.join(dir, '.git'), { recursive: true });
    fs.writeFileSync(path.join(dir, '.git', 'config.json'), '{}');
    fs.writeFileSync(path.join(dir, 'config.json'), '{}');

    const files = await findFiles(dir, ['**/*.json']);
    expect(files.some(f => f.includes('.git'))).toBe(false);
  });

  test('DerivedData is always excluded', async () => {
    const dir = path.join(TEMP_DIR, 'derived-exclude');
    fs.mkdirSync(path.join(dir, 'DerivedData'), { recursive: true });
    fs.writeFileSync(path.join(dir, 'DerivedData', 'tool.js'), 'x');
    fs.writeFileSync(path.join(dir, 'tool.js'), 'y');

    const files = await findFiles(dir, ['**/*.js']);
    expect(files.some(f => f.includes('DerivedData'))).toBe(false);
  });
});

// ========== Profile filtering ==========
describe('filterScannersByProfile', () => {
  test('agent profile returns all scanners', () => {
    const result = filterScannersByProfile(ALL_SCANNERS, 'agent');
    expect(result.length).toBe(7);
  });

  test('general profile returns Secret Leak, Permission, Skill Auditor', () => {
    const result = filterScannersByProfile(ALL_SCANNERS, 'general');
    expect(result.length).toBe(3);
    const names = result.map(s => s.name);
    expect(names).toContain('Secret Leak Scanner');
    expect(names).toContain('Permission Analyzer');
    expect(names).toContain('Skill Auditor');
    expect(names).not.toContain('Defense Analyzer');
    expect(names).not.toContain('Red Team Simulator');
    expect(names).not.toContain('Prompt Injection Tester');
    expect(names).not.toContain('MCP Config Auditor');
  });

  test('mobile profile returns Secret Leak and Permission only', () => {
    const result = filterScannersByProfile(ALL_SCANNERS, 'mobile');
    expect(result.length).toBe(2);
    const names = result.map(s => s.name);
    expect(names).toContain('Secret Leak Scanner');
    expect(names).toContain('Permission Analyzer');
  });

  test('agent profile includes AI-specific scanners', () => {
    const result = filterScannersByProfile(ALL_SCANNERS, 'agent');
    const names = result.map(s => s.name);
    expect(names).toContain('Defense Analyzer');
    expect(names).toContain('Red Team Simulator');
    expect(names).toContain('Prompt Injection Tester');
    expect(names).toContain('MCP Config Auditor');
  });
});

// ========== --scanners takes priority over --profile ==========
describe('scanners vs profile priority', () => {
  test('--scanners flag should override profile in runScan logic', () => {
    // This tests the filterScannersByProfile function itself
    // The actual priority logic is in runScan (if scanners specified, profile is ignored)
    // We test the building blocks here
    const mobileResult = filterScannersByProfile(ALL_SCANNERS, 'mobile');
    expect(mobileResult.length).toBe(2);

    // With --scanners, all 7 are available to filter from
    // (the actual runScan filters SCANNERS by name match, ignoring profile)
    const defenseOnly = ALL_SCANNERS.filter(s =>
      s.name.toLowerCase().includes('defense')
    );
    expect(defenseOnly.length).toBe(1);
    expect(defenseOnly[0].name).toBe('Defense Analyzer');
  });
});
