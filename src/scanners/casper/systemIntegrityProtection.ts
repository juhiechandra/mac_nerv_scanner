import { runCommand } from '../../core/shell.js';
import { buildFinding } from '../../core/finding.js';
import type { Finding, Scanner } from '../../core/types.js';

const SCANNER_ID = 'casper.sip';

async function readSipStatus(): Promise<string> {
  const result = await runCommand('csrutil', ['status']);
  return result.stdout.trim();
}

function isProtectionEnabled(output: string): boolean {
  return /enabled/i.test(output) && !/disabled/i.test(output);
}

async function* scanSip(): AsyncIterable<Finding> {
  const status = await readSipStatus();
  const enabled = isProtectionEnabled(status);
  yield buildFinding({
    scannerId: SCANNER_ID,
    magi: 'casper',
    pattern: enabled ? 'blue' : 'red',
    title: enabled ? 'System Integrity Protection is enabled' : 'System Integrity Protection is DISABLED',
    evidence: status,
    remediation: enabled ? undefined : 'Re-enable SIP from Recovery: csrutil enable, then reboot.',
    references: ['https://support.apple.com/en-us/HT204899'],
  });
}

export const sipScanner: Scanner = {
  id: SCANNER_ID,
  title: 'System Integrity Protection',
  magi: 'casper',
  run: scanSip,
};
