import { runCommand, commandFailed, describeFailure } from '../../core/shell.js';
import { buildFinding } from '../../core/finding.js';
import type { Finding, Scanner } from '../../core/types.js';

const SCANNER_ID = 'casper.filevault';

async function* scanFileVault(): AsyncIterable<Finding> {
  const status = await runCommand('fdesetup', ['status']);

  if (commandFailed(status)) {
    yield buildFinding({
      scannerId: SCANNER_ID,
      magi: 'casper',
      pattern: 'yellow',
      title: 'FileVault status unavailable',
      evidence: describeFailure(status),
    });
    return;
  }

  const text = status.stdout.trim();
  const enabled = /FileVault is On/i.test(text);

  yield buildFinding({
    scannerId: SCANNER_ID,
    magi: 'casper',
    pattern: enabled ? 'blue' : 'orange',
    title: enabled ? 'FileVault encryption is on' : 'FileVault encryption is OFF',
    evidence: text || 'fdesetup returned empty output',
    remediation: enabled ? undefined : 'Enable FileVault under System Settings → Privacy & Security → FileVault.',
    references: ['https://support.apple.com/guide/mac-help/protect-data-on-your-mac-with-filevault-mh11785'],
  });

  if (!enabled) return;

  const recovery = await runCommand('fdesetup', ['haspersonalrecoverykey']);
  if (commandFailed(recovery)) {
    yield buildFinding({
      scannerId: SCANNER_ID,
      magi: 'casper',
      pattern: 'yellow',
      title: 'FileVault recovery key status requires admin',
      evidence: describeFailure(recovery),
      remediation: 'Re-run with sudo to confirm a personal recovery key is set.',
    });
    return;
  }

  const hasKey = /true/i.test(recovery.stdout.trim());
  yield buildFinding({
    scannerId: SCANNER_ID,
    magi: 'casper',
    pattern: hasKey ? 'blue' : 'yellow',
    title: hasKey ? 'FileVault personal recovery key is set' : 'FileVault has no personal recovery key',
    evidence: recovery.stdout.trim() || '(no output)',
    remediation: hasKey
      ? undefined
      : 'Generate a recovery key: sudo fdesetup changerecovery -personal — store it offline.',
  });
}

export const fileVaultScanner: Scanner = {
  id: SCANNER_ID,
  title: 'FileVault Encryption',
  magi: 'casper',
  run: scanFileVault,
};
