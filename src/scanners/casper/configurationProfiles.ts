import { runCommand, commandFailed, describeFailure } from '../../core/shell.js';
import { buildFinding } from '../../core/finding.js';
import type { Finding, Scanner } from '../../core/types.js';

const SCANNER_ID = 'casper.config-profiles';

async function readInstalledProfiles() {
  return runCommand('profiles', ['-P']);
}

function noProfilesInstalled(stdout: string): boolean {
  return /there are no/i.test(stdout) || stdout.trim().length === 0;
}

async function* scanConfigurationProfiles(): AsyncIterable<Finding> {
  const result = await readInstalledProfiles();

  if (commandFailed(result)) {
    yield buildFinding({
      scannerId: SCANNER_ID,
      magi: 'casper',
      pattern: 'yellow',
      title: 'Configuration profile list unavailable',
      evidence: describeFailure(result),
      remediation: 'profiles -P may require admin on some macOS versions; re-run with elevated privileges.',
    });
    return;
  }

  const stdout = result.stdout.trim();
  const present = !noProfilesInstalled(stdout);

  yield buildFinding({
    scannerId: SCANNER_ID,
    magi: 'casper',
    pattern: present ? 'yellow' : 'blue',
    title: present ? 'Configuration profiles detected' : 'No configuration profiles installed',
    evidence: stdout || 'No profiles.',
    remediation: present ? 'Audit each profile under System Settings → Privacy & Security → Profiles.' : undefined,
  });
}

export const configurationProfilesScanner: Scanner = {
  id: SCANNER_ID,
  title: 'Configuration Profiles (MDM)',
  magi: 'casper',
  run: scanConfigurationProfiles,
};
