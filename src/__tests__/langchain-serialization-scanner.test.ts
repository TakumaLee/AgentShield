import { describe, it, expect, beforeAll, afterAll } from '@jest/globals';
import * as fs from 'fs-extra';
import * as path from 'path';
import { LangChainSerializationScanner } from '../scanners/langchain-serialization-scanner';

describe('LangChain Serialization Scanner', () => {
  const testDir = path.join(__dirname, '../../test-data/langchain-serialization-scanner');
  const scanner = new LangChainSerializationScanner();

  beforeAll(async () => {
    await fs.ensureDir(testDir);
  });

  afterAll(async () => {
    await fs.remove(testDir);
  });

  it('should detect pickle.load with allow_dangerous_deserialization=True (CRITICAL)', async () => {
    const testFile = path.join(testDir, 'pickle-unsafe.py');
    await fs.writeFile(
      testFile,
      `
import pickle

# Unsafe deserialization
with open('chain.pkl', 'rb') as f:
    chain = pickle.load(f, allow_dangerous_deserialization=True)
`
    );

    const result = await scanner.scan(testDir);
    const finding = result.findings.find(f => f.file?.includes('pickle-unsafe.py'));
    
    expect(finding).toBeDefined();
    expect(finding?.severity).toBe('critical');
    expect(finding?.rule).toBe('LANGCHAIN-001');
    expect(finding?.message).toContain('Unsafe pickle deserialization');
    expect(finding?.recommendation).toContain('JSON');
  });

  it('should detect pickle.loads with unsafe=True (CRITICAL)', async () => {
    const testFile = path.join(testDir, 'pickle-loads-unsafe.py');
    await fs.writeFile(
      testFile,
      `
import pickle

data = request.get_data()
obj = pickle.loads(data, unsafe=True)
`
    );

    const result = await scanner.scan(testDir);
    const finding = result.findings.find(f => f.file?.includes('pickle-loads-unsafe.py'));
    
    expect(finding).toBeDefined();
    expect(finding?.severity).toBe('critical');
    expect(finding?.rule).toBe('LANGCHAIN-001');
  });

  it('should detect yaml.load without Loader parameter (HIGH)', async () => {
    const testFile = path.join(testDir, 'yaml-unsafe.py');
    await fs.writeFile(
      testFile,
      `
import yaml

with open('config.yaml', 'r') as f:
    config = yaml.load(f)
`
    );

    const result = await scanner.scan(testDir);
    const finding = result.findings.find(f => f.file?.includes('yaml-unsafe.py'));
    
    expect(finding).toBeDefined();
    expect(finding?.severity).toBe('high');
    expect(finding?.rule).toBe('LANGCHAIN-002');
    expect(finding?.message).toContain('Unsafe YAML deserialization');
    expect(finding?.recommendation).toContain('safe_load');
  });

  it('should NOT flag yaml.safe_load (safe usage)', async () => {
    const testFile = path.join(testDir, 'yaml-safe.py');
    await fs.writeFile(
      testFile,
      `
import yaml

with open('config.yaml', 'r') as f:
    config = yaml.safe_load(f)
`
    );

    const result = await scanner.scan(testDir);
    const finding = result.findings.find(f => f.file?.includes('yaml-safe.py'));
    
    expect(finding).toBeUndefined();
  });

  it('should NOT flag yaml.load with SafeLoader (safe usage)', async () => {
    const testFile = path.join(testDir, 'yaml-safe-loader.py');
    await fs.writeFile(
      testFile,
      `
import yaml

with open('config.yaml', 'r') as f:
    config = yaml.load(f, Loader=yaml.SafeLoader)
`
    );

    const result = await scanner.scan(testDir);
    const finding = result.findings.find(f => f.file?.includes('yaml-safe-loader.py'));
    
    expect(finding).toBeUndefined();
  });

  it('should detect chain loading from user input (HIGH)', async () => {
    const testFile = path.join(testDir, 'chain-load-user-input.py');
    await fs.writeFile(
      testFile,
      `
from langchain.chains import load_chain

chain_path = request.args.get('chain_path')
chain = load_chain(chain_path)
`
    );

    const result = await scanner.scan(testDir);
    const finding = result.findings.find(f => f.file?.includes('chain-load-user-input.py'));
    
    expect(finding).toBeDefined();
    expect(finding?.severity).toBe('high');
    expect(finding?.rule).toBe('LANGCHAIN-003');
    expect(finding?.message).toContain('untrusted source');
  });

  it('should detect agent loading from environment variable (HIGH)', async () => {
    const testFile = path.join(testDir, 'agent-load-env.py');
    await fs.writeFile(
      testFile,
      `
from langchain.agents import load_agent
import os

agent_path = os.environ.get('AGENT_PATH')
agent = load_agent(agent_path)
`
    );

    const result = await scanner.scan(testDir);
    const finding = result.findings.find(f => f.file?.includes('agent-load-env.py'));
    
    expect(finding).toBeDefined();
    expect(finding?.severity).toBe('high');
    expect(finding?.rule).toBe('LANGCHAIN-003');
  });

  it('should detect .load with path from argv (HIGH)', async () => {
    const testFile = path.join(testDir, 'load-from-argv.py');
    await fs.writeFile(
      testFile,
      `
import sys
from langchain import SomeClass

config_path = sys.argv[1]
obj = SomeClass.load(config_path)
`
    );

    const result = await scanner.scan(testDir);
    const finding = result.findings.find(f => f.file?.includes('load-from-argv.py'));
    
    expect(finding).toBeDefined();
    expect(finding?.severity).toBe('high');
    expect(finding?.rule).toBe('LANGCHAIN-003');
    expect(finding?.recommendation).toContain('Validate');
  });

  it('should NOT flag safe hardcoded chain loading', async () => {
    const testFile = path.join(testDir, 'chain-load-safe.py');
    await fs.writeFile(
      testFile,
      `
from langchain.chains import load_chain

# Safe: hardcoded path
chain = load_chain('./configs/my_chain.json')
`
    );

    const result = await scanner.scan(testDir);
    const finding = result.findings.find(f => f.file?.includes('chain-load-safe.py'));
    
    // Should not flag hardcoded paths without user input indicators
    expect(finding).toBeUndefined();
  });

  it('should handle multiple vulnerabilities in one file', async () => {
    const testFile = path.join(testDir, 'multiple-vulns.py');
    await fs.writeFile(
      testFile,
      `
import pickle
import yaml

# Vulnerability 1: unsafe pickle
with open('data.pkl', 'rb') as f:
    data = pickle.load(f, allow_dangerous_deserialization=True)

# Vulnerability 2: unsafe yaml
with open('config.yaml', 'r') as f:
    config = yaml.load(f)
`
    );

    const result = await scanner.scan(testDir);
    const findings = result.findings.filter(f => f.file?.includes('multiple-vulns.py'));
    
    expect(findings.length).toBeGreaterThanOrEqual(2);
    expect(findings.some(f => f.rule === 'LANGCHAIN-001')).toBe(true);
    expect(findings.some(f => f.rule === 'LANGCHAIN-002')).toBe(true);
  });

  it('should provide proper recommendations for all findings', async () => {
    const testFile = path.join(testDir, 'recommendations.py');
    await fs.writeFile(
      testFile,
      `
import pickle
import yaml
from langchain.chains import load_chain

pickle.load(file, allow_dangerous_deserialization=True)
yaml.load(file)
load_chain(request.path)
`
    );

    const result = await scanner.scan(testDir);
    
    expect(result.findings.length).toBeGreaterThan(0);
    result.findings.forEach(finding => {
      expect(finding.recommendation).toBeDefined();
      expect(finding.recommendation!.length).toBeGreaterThan(10);
    });
  });

  it('should scan TypeScript files for yaml patterns', async () => {
    const testFile = path.join(testDir, 'yaml-ts.ts');
    await fs.writeFile(
      testFile,
      `
import * as yaml from 'js-yaml';

const config = yaml.load(fileContent);
`
    );

    const result = await scanner.scan(testDir);
    const finding = result.findings.find(f => f.file?.includes('yaml-ts.ts'));
    
    expect(finding).toBeDefined();
    expect(finding?.rule).toBe('LANGCHAIN-002');
  });

  it('should report correct scanner name and scanned files count', async () => {
    const result = await scanner.scan(testDir);
    
    expect(result.scanner).toBe('LangChainSerializationScanner');
    expect(result.scannedFiles).toBeGreaterThan(0);
    expect(result.duration).toBeGreaterThanOrEqual(0);
  });
});
