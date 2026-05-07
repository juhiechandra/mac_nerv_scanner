import { runCommand } from '../../core/shell.js';
import { buildFinding } from '../../core/finding.js';
import type { Finding, Scanner } from '../../core/types.js';

const SCANNER_ID = 'casper.config-profiles';

async function readInstalledProfiles(): Promise<string> {
  const result = await runCommand('profiles', ['list']);
  return (result.stdout + result.stderr).trim();
}

function hasProfilesInstalled(output: string): boolean {
  return /attribute:\s*name/i.test(output);
}

async function* scanConfigurationProfiles(): AsyncIterable<Finding> {
  const output = await readInstalledProfiles();
  const present = hasProfilesInstalled(output);
  yield buildFinding({
    scannerId: SCANNER_ID,
    magi: 'casper',
    pattern: present ? 'yellow' : 'blue',
    title: present ? 'Configuration profiles detected' : 'No configuration profiles installed',
    evidence: output || 'profiles command returned no data',
    remediation: present ? 'Audit each profile under System Settings → Privacy & Security → Profiles.' : undefined,
  });
}

export const configurationProfilesScanner: Scanner = {
  id: SCANNER_ID,
  title: 'Configuration Profiles (MDM)',
  magi: 'casper',
  run: scanConfigurationProfiles,
};
