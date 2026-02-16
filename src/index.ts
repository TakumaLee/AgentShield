export { ScannerRegistry } from './scanner-registry';
export { SupplyChainScanner } from './scanners/supply-chain-scanner';
export { HygieneAuditor } from './scanners/hygiene-auditor';
export { DxtSecurityScanner } from './scanners/dxt-security-scanner';
export { VisualPromptInjectionScanner } from './scanners/visual-prompt-injection-scanner';
export { LangChainSerializationScanner } from './scanners/langchain-serialization-scanner';
export { walkFiles } from './utils/file-walker';
export * from './types';

import { ScannerRegistry } from './scanner-registry';
import { SupplyChainScanner } from './scanners/supply-chain-scanner';
import { HygieneAuditor } from './scanners/hygiene-auditor';
import { DxtSecurityScanner } from './scanners/dxt-security-scanner';
import { VisualPromptInjectionScanner } from './scanners/visual-prompt-injection-scanner';
import { LangChainSerializationScanner } from './scanners/langchain-serialization-scanner';

export function createDefaultRegistry(externalIOCPath?: string): ScannerRegistry {
  const registry = new ScannerRegistry();
  registry.register(new SupplyChainScanner(externalIOCPath));
  registry.register(new HygieneAuditor());
  registry.register(new DxtSecurityScanner());
  registry.register(new VisualPromptInjectionScanner());
  registry.register(new LangChainSerializationScanner());
  return registry;
}
