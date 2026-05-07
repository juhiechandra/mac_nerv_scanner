import { runCommand } from '../../core/shell.js';
import { buildFinding } from '../../core/finding.js';
import type { Finding, Pattern, Scanner } from '../../core/types.js';

const SCANNER_ID = 'balthasar.screen-lock';

async function readPreference(domain: string, key: string): Promise<string | null> {
  const result = await runCommand('defaults', ['read', domain, key]);
  if (result.exitCode !== 0) return null;
  return result.stdout.trim();
}

function classifyDelay(delaySeconds: number | null): Pattern {
  if (delaySeconds === null) return 'yellow';
  if (delaySeconds === 0) return 'blue';
  if (delaySeconds <= 60) return 'yellow';
  return 'orange';
}

async function* scanScreenLockPolicy(): AsyncIterable<Finding> {
  const askPassword = await readPreference('com.apple.screensaver', 'askForPassword');
  const askDelayRaw = await readPreference('com.apple.screensaver', 'askForPasswordDelay');
  const askDelay = askDelayRaw !== null ? Number(askDelayRaw) : null;

  const enforced = askPassword === '1';

  yield buildFinding({
    scannerId: SCANNER_ID,
    magi: 'balthasar',
    pattern: enforced ? 'blue' : 'orange',
    title: enforced ? 'Screen lock requires password' : 'Screen lock does NOT require password',
    evidence: `askForPassword=${askPassword ?? '(unset)'}, askForPasswordDelay=${askDelayRaw ?? '(unset)'}`,
    remediation: enforced
      ? undefined
      : 'Enable: defaults write com.apple.screensaver askForPassword -int 1',
  });

  yield buildFinding({
    scannerId: SCANNER_ID,
    magi: 'balthasar',
    pattern: classifyDelay(askDelay),
    title: `Password required ${askDelay === null ? 'unknown delay' : `${askDelay}s after lock`}`,
    evidence: `askForPasswordDelay=${askDelayRaw ?? '(unset)'}`,
    remediation:
      askDelay !== null && askDelay > 0
        ? 'Set delay to 0: defaults write com.apple.screensaver askForPasswordDelay -int 0'
        : undefined,
  });
}

export const screenLockPolicyScanner: Scanner = {
  id: SCANNER_ID,
  title: 'Screen Lock Policy',
  magi: 'balthasar',
  run: scanScreenLockPolicy,
};
