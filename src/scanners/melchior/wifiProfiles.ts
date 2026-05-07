import { runCommand } from '../../core/shell.js';
import { buildFinding } from '../../core/finding.js';
import { maybeRedact } from '../../core/redact.js';
import type { Finding, ScanContext, Scanner } from '../../core/types.js';

const SCANNER_ID = 'melchior.wifi-profiles';

async function readPreferredNetworks(): Promise<string> {
  const result = await runCommand('networksetup', ['-listpreferredwirelessnetworks', 'en0']);
  return (result.stdout + result.stderr).trim();
}

function countNetworks(output: string): number {
  return output
    .split('\n')
    .map((line) => line.trim())
    .filter((line) => line.length > 0 && !/preferred wireless networks/i.test(line)).length;
}

async function* scanWifiProfiles(context: ScanContext): AsyncIterable<Finding> {
  const output = await readPreferredNetworks();
  const count = countNetworks(output);
  yield buildFinding({
    scannerId: SCANNER_ID,
    magi: 'melchior',
    pattern: count > 25 ? 'yellow' : 'blue',
    title: `${count} preferred Wi-Fi network(s) saved`,
    evidence: maybeRedact(output, context.redact),
    remediation:
      count > 25
        ? 'Prune stale Wi-Fi profiles; each one is a potential KARMA-style impersonation surface.'
        : undefined,
  });
}

export const wifiProfilesScanner: Scanner = {
  id: SCANNER_ID,
  title: 'Saved Wi-Fi Networks',
  magi: 'melchior',
  run: scanWifiProfiles,
};
