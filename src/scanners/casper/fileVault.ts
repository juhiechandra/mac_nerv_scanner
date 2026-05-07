import { runCommand } from '../../core/shell.js';
import { buildFinding } from '../../core/finding.js';
import type { Finding, Scanner } from '../../core/types.js';

const SCANNER_ID = 'casper.filevault';

async function readFileVaultStatus(): Promise<string> {
  const result = await runCommand('fdesetup', ['status']);
  return result.stdout.trim();
}

function isFileVaultOn(status: string): boolean {
  return /FileVault is On/i.test(status);
}

async function* scanFileVault(): AsyncIterable<Finding> {
  const status = await readFileVaultStatus();
  const enabled = isFileVaultOn(status);
  yield buildFinding({
    scannerId: SCANNER_ID,
    magi: 'casper',
    pattern: enabled ? 'blue' : 'orange',
    title: enabled ? 'FileVault encryption is on' : 'FileVault encryption is OFF',
    evidence: status || 'fdesetup returned empty output',
    remediation: enabled ? undefined : 'Enable FileVault under System Settings → Privacy & Security → FileVault.',
    references: ['https://support.apple.com/guide/mac-help/protect-data-on-your-mac-with-filevault-mh11785'],
  });
}

export const fileVaultScanner: Scanner = {
  id: SCANNER_ID,
  title: 'FileVault Encryption',
  magi: 'casper',
  run: scanFileVault,
};
