import * as fs from 'fs';
import * as path from 'path';
import {
  readFileContent,
  fileExists,
  isTestOrDocFile,
  findFiles,
  findConfigFiles,
  findPromptFiles,
  isJsonFile,
  isYamlFile,
  tryParseJson,
} from '../src/utils/file-utils';

// Create a temp directory for tests
const TEMP_DIR = path.join(__dirname, '__temp_file_utils__');

beforeAll(() => {
  if (!fs.existsSync(TEMP_DIR)) {
    fs.mkdirSync(TEMP_DIR, { recursive: true });
  }
});

afterAll(() => {
  fs.rmSync(TEMP_DIR, { recursive: true, force: true });
});

describe('file-utils', () => {
  // === readFileContent ===
  describe('readFileContent', () => {
    test('reads file content as UTF-8 string', () => {
      const filePath = path.join(TEMP_DIR, 'test-read.txt');
      fs.writeFileSync(filePath, 'hello world', 'utf-8');
      expect(readFileContent(filePath)).toBe('hello world');
    });

    test('throws on non-existent file', () => {
      expect(() => readFileContent('/non/existent/file.txt')).toThrow();
    });
  });

  // === fileExists ===
  describe('fileExists', () => {
    test('returns true for existing file', () => {
      const filePath = path.join(TEMP_DIR, 'exists.txt');
      fs.writeFileSync(filePath, 'data');
      expect(fileExists(filePath)).toBe(true);
    });

    test('returns false for non-existent file', () => {
      expect(fileExists(path.join(TEMP_DIR, 'nope.txt'))).toBe(false);
    });
  });

  // === isTestOrDocFile ===
  describe('isTestOrDocFile', () => {
    test('detects test directory paths', () => {
      expect(isTestOrDocFile('/project/tests/foo.ts')).toBe(true);
      expect(isTestOrDocFile('/project/__tests__/bar.ts')).toBe(true);
      expect(isTestOrDocFile('/project/spec/baz.ts')).toBe(true);
    });

    test('detects test file extensions', () => {
      expect(isTestOrDocFile('foo.test.ts')).toBe(true);
      expect(isTestOrDocFile('bar.spec.js')).toBe(true);
      expect(isTestOrDocFile('baz.test.jsx')).toBe(true);
    });

    test('detects doc/example files', () => {
      expect(isTestOrDocFile('README.md')).toBe(true);
      expect(isTestOrDocFile('CHANGELOG.md')).toBe(true);
      expect(isTestOrDocFile('CONTRIBUTING.md')).toBe(true);
      expect(isTestOrDocFile('/project/docs/guide.md')).toBe(true);
      expect(isTestOrDocFile('/project/examples/demo.ts')).toBe(true);
    });

    test('detects fixtures and mocks', () => {
      expect(isTestOrDocFile('/project/fixtures/data.json')).toBe(true);
      expect(isTestOrDocFile('/project/mocks/api.ts')).toBe(true);
    });

    test('returns false for normal source files', () => {
      expect(isTestOrDocFile('/project/src/index.ts')).toBe(false);
      expect(isTestOrDocFile('/project/lib/utils.js')).toBe(false);
    });
  });

  // === isJsonFile / isYamlFile ===
  describe('isJsonFile', () => {
    test('detects .json files', () => {
      expect(isJsonFile('config.json')).toBe(true);
      expect(isJsonFile('data.JSON')).toBe(true);
    });

    test('rejects non-json files', () => {
      expect(isJsonFile('config.yaml')).toBe(false);
      expect(isJsonFile('config.ts')).toBe(false);
    });
  });

  describe('isYamlFile', () => {
    test('detects .yaml and .yml files', () => {
      expect(isYamlFile('config.yaml')).toBe(true);
      expect(isYamlFile('config.yml')).toBe(true);
      expect(isYamlFile('config.YAML')).toBe(true);
    });

    test('rejects non-yaml files', () => {
      expect(isYamlFile('config.json')).toBe(false);
      expect(isYamlFile('config.ts')).toBe(false);
    });
  });

  // === tryParseJson ===
  describe('tryParseJson', () => {
    test('parses valid JSON', () => {
      expect(tryParseJson('{"a": 1}')).toEqual({ a: 1 });
      expect(tryParseJson('[1,2,3]')).toEqual([1, 2, 3]);
      expect(tryParseJson('"hello"')).toBe('hello');
    });

    test('returns null for invalid JSON', () => {
      expect(tryParseJson('not json')).toBeNull();
      expect(tryParseJson('{broken')).toBeNull();
      expect(tryParseJson('')).toBeNull();
    });
  });

  // === findFiles ===
  describe('findFiles', () => {
    test('finds files matching patterns', async () => {
      const subDir = path.join(TEMP_DIR, 'find-test');
      fs.mkdirSync(subDir, { recursive: true });
      fs.writeFileSync(path.join(subDir, 'a.json'), '{}');
      fs.writeFileSync(path.join(subDir, 'b.txt'), 'text');

      const results = await findFiles(subDir, ['**/*.json']);
      expect(results.length).toBe(1);
      expect(results[0]).toContain('a.json');
    });

    test('deduplicates results from multiple patterns', async () => {
      const subDir = path.join(TEMP_DIR, 'dedup-test');
      fs.mkdirSync(subDir, { recursive: true });
      fs.writeFileSync(path.join(subDir, 'config.json'), '{}');

      const results = await findFiles(subDir, ['**/*.json', '**/config.*']);
      expect(results.length).toBe(1);
    });

    test('skips oversized files', async () => {
      const subDir = path.join(TEMP_DIR, 'size-test');
      fs.mkdirSync(subDir, { recursive: true });
      // Create a file larger than 256KB
      const bigContent = 'x'.repeat(257 * 1024);
      fs.writeFileSync(path.join(subDir, 'big.txt'), bigContent);
      fs.writeFileSync(path.join(subDir, 'small.txt'), 'small');

      const results = await findFiles(subDir, ['**/*.txt']);
      expect(results.length).toBe(1);
      expect(results[0]).toContain('small.txt');
    });

    test('returns empty array for no matches', async () => {
      const subDir = path.join(TEMP_DIR, 'empty-find');
      fs.mkdirSync(subDir, { recursive: true });
      const results = await findFiles(subDir, ['**/*.xyz']);
      expect(results.length).toBe(0);
    });
  });

  // === findConfigFiles ===
  describe('findConfigFiles', () => {
    test('finds config files by extension', async () => {
      const subDir = path.join(TEMP_DIR, 'config-find');
      fs.mkdirSync(subDir, { recursive: true });
      fs.writeFileSync(path.join(subDir, 'mcp-config.json'), '{}');
      fs.writeFileSync(path.join(subDir, 'settings.yaml'), 'key: val');
      fs.writeFileSync(path.join(subDir, '.env'), 'VAR=1');

      const results = await findConfigFiles(subDir);
      expect(results.length).toBeGreaterThanOrEqual(3);
    });
  });

  // === findPromptFiles ===
  describe('findPromptFiles', () => {
    test('finds prompt/agent related files', async () => {
      const subDir = path.join(TEMP_DIR, 'prompt-find');
      fs.mkdirSync(subDir, { recursive: true });
      fs.writeFileSync(path.join(subDir, 'system-prompt.md'), '# System');
      fs.writeFileSync(path.join(subDir, 'AGENTS.md'), '# Agents');
      fs.writeFileSync(path.join(subDir, 'random.txt'), 'hello');

      const results = await findPromptFiles(subDir);
      expect(results.length).toBeGreaterThanOrEqual(2);
    });
  });
});
