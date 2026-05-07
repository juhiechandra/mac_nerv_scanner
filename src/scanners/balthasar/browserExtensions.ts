import { readdir } from 'node:fs/promises';
import { homedir } from 'node:os';
import { join } from 'node:path';
import { buildFinding, classifyByThreshold } from '../../core/finding.js';
import type { Finding, Pattern, Scanner } from '../../core/types.js';

const SCANNER_ID = 'balthasar.browser-extensions';

interface BrowserTarget {
  name: string;
  path: string;
}

function browserTargets(): BrowserTarget[] {
  const home = homedir();
  return [
    { name: 'Chrome', path: join(home, 'Library', 'Application Support', 'Google', 'Chrome', 'Default', 'Extensions') },
    { name: 'Brave', path: join(home, 'Library', 'Application Support', 'BraveSoftware', 'Brave-Browser', 'Default', 'Extensions') },
    { name: 'Edge', path: join(home, 'Library', 'Application Support', 'Microsoft Edge', 'Default', 'Extensions') },
    { name: 'Arc', path: join(home, 'Library', 'Application Support', 'Arc', 'User Data', 'Default', 'Extensions') },
  ];
}

async function countExtensions(target: BrowserTarget): Promise<number> {
  try {
    const entries = await readdir(target.path);
    return entries.filter((entry) => !entry.startsWith('.') && entry !== 'Temp').length;
  } catch {
    return 0;
  }
}

function classifyExtensionCount(count: number): Pattern {
  return classifyByThreshold(count, { yellow: 10, orange: 20 });
}

async function* scanBrowserExtensions(): AsyncIterable<Finding> {
  for (const target of browserTargets()) {
    const count = await countExtensions(target);
    if (count === 0) continue;
    yield buildFinding({
      scannerId: SCANNER_ID,
      magi: 'balthasar',
      pattern: classifyExtensionCount(count),
      title: `${target.name}: ${count} extension(s) installed`,
      evidence: target.path,
      remediation:
        count > 10
          ? 'Audit installed extensions; malicious ones can read every page you visit.'
          : undefined,
    });
  }
}

export const browserExtensionsScanner: Scanner = {
  id: SCANNER_ID,
  title: 'Browser Extensions',
  magi: 'balthasar',
  run: scanBrowserExtensions,
};
