import { runCommand, commandFailed, describeFailure } from '../../core/shell.js';
import { buildFinding } from '../../core/finding.js';
import type { Finding, Scanner } from '../../core/types.js';

const SCANNER_ID = 'casper.software-updates';
const TIMEOUT_MS = 45000;

async function listAvailableUpdates() {
  return runCommand('softwareupdate', ['-l'], { timeoutMs: TIMEOUT_MS });
}

function countOfferedUpdates(stdout: string): number {
  const labelMatches = stdout.match(/^\s*\*\s*Label:/gm);
  if (labelMatches) return labelMatches.length;
  const legacyMatches = stdout.match(/^\s*\*\s+\S/gm);
  return legacyMatches ? legacyMatches.length : 0;
}

function classifyUpdateCount(count: number): 'blue' | 'yellow' | 'orange' {
  if (count === 0) return 'blue';
  if (count <= 2) return 'yellow';
  return 'orange';
}

async function* scanSoftwareUpdates(): AsyncIterable<Finding> {
  const result = await listAvailableUpdates();

  if (commandFailed(result)) {
    yield buildFinding({
      scannerId: SCANNER_ID,
      magi: 'casper',
      pattern: 'yellow',
      title: 'Software update check failed',
      evidence: describeFailure(result),
      remediation: 'Check network connectivity and retry; softwareupdate -l requires Apple servers.',
    });
    return;
  }

  const stdout = result.stdout.trim();
  const count = countOfferedUpdates(stdout);

  yield buildFinding({
    scannerId: SCANNER_ID,
    magi: 'casper',
    pattern: classifyUpdateCount(count),
    title: count === 0 ? 'macOS is up to date' : `${count} pending macOS update(s)`,
    evidence: stdout || 'softwareupdate returned no data',
    remediation: count > 0 ? 'Install via System Settings → General → Software Update.' : undefined,
  });
}

export const softwareUpdatesScanner: Scanner = {
  id: SCANNER_ID,
  title: 'Software Updates',
  magi: 'casper',
  run: scanSoftwareUpdates,
};
