import { runCommand, commandFailed, describeFailure } from '../../core/shell.js';
import { buildFinding } from '../../core/finding.js';
import { maybeRedact, registerSensitiveValue } from '../../core/redact.js';
import type { Finding, ScanContext, Scanner } from '../../core/types.js';

const SCANNER_ID = 'melchior.wifi-profiles';

async function findWifiInterface(): Promise<string | null> {
  const result = await runCommand('networksetup', ['-listallhardwareports']);
  if (commandFailed(result)) return null;
  const lines = result.stdout.split('\n');
  for (let i = 0; i < lines.length; i += 1) {
    if (/^Hardware Port:\s+Wi-Fi/i.test(lines[i] ?? '')) {
      const deviceMatch = lines[i + 1]?.match(/^Device:\s+(\S+)/);
      if (deviceMatch?.[1]) return deviceMatch[1];
    }
  }
  return null;
}

function parseNetworks(stdout: string): string[] {
  return stdout
    .split('\n')
    .map((line) => line.trim())
    .filter((line) => line.length > 0 && !/preferred wireless networks/i.test(line));
}

async function* scanWifiProfiles(context: ScanContext): AsyncIterable<Finding> {
  const iface = await findWifiInterface();

  if (!iface) {
    yield buildFinding({
      scannerId: SCANNER_ID,
      magi: 'melchior',
      pattern: 'blue',
      title: 'No Wi-Fi interface detected',
      evidence: 'networksetup -listallhardwareports has no Wi-Fi entry.',
    });
    return;
  }

  const result = await runCommand('networksetup', ['-listpreferredwirelessnetworks', iface]);
  if (commandFailed(result)) {
    yield buildFinding({
      scannerId: SCANNER_ID,
      magi: 'melchior',
      pattern: 'yellow',
      title: 'Wi-Fi profile list unavailable',
      evidence: describeFailure(result),
    });
    return;
  }

  const networks = parseNetworks(result.stdout);
  if (context.redact) {
    for (const ssid of networks) registerSensitiveValue(ssid);
  }

  yield buildFinding({
    scannerId: SCANNER_ID,
    magi: 'melchior',
    pattern: networks.length > 25 ? 'yellow' : 'blue',
    title: `${networks.length} preferred Wi-Fi network(s) saved on ${iface}`,
    evidence: maybeRedact(networks.join('\n') || '(none)', context.redact),
    remediation:
      networks.length > 25
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
