import { runCommand } from '../../core/shell.js';
import { buildFinding } from '../../core/finding.js';
import type { Finding, Scanner } from '../../core/types.js';

const SCANNER_ID = 'casper.software-updates';

async function listAvailableUpdates(): Promise<string> {
  const result = await runCommand('softwareupdate', ['-l'], { timeoutMs: 25000 });
  return (result.stdout + result.stderr).trim();
}

function countOfferedUpdates(output: string): number {
  const matches = output.match(/^\*\s.+$/gm);
  return matches ? matches.length : 0;
}

function classifyUpdateCount(count: number): 'blue' | 'yellow' | 'orange' {
  if (count === 0) return 'blue';
  if (count <= 2) return 'yellow';
  return 'orange';
}

async function* scanSoftwareUpdates(): AsyncIterable<Finding> {
  const output = await listAvailableUpdates();
  const count = countOfferedUpdates(output);
  yield buildFinding({
    scannerId: SCANNER_ID,
    magi: 'casper',
    pattern: classifyUpdateCount(count),
    title: count === 0 ? 'macOS is up to date' : `${count} pending macOS update(s)`,
    evidence: output || 'softwareupdate returned no data',
    remediation: count > 0 ? 'Install via System Settings → General → Software Update.' : undefined,
  });
}

export const softwareUpdatesScanner: Scanner = {
  id: SCANNER_ID,
  title: 'Software Updates',
  magi: 'casper',
  run: scanSoftwareUpdates,
};
