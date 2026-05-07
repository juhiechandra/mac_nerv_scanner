import { runCommand } from '../../core/shell.js';
import { buildFinding } from '../../core/finding.js';
import type { Finding, Pattern, Scanner } from '../../core/types.js';

const SCANNER_ID = 'melchior.sharing-services';

const SHARING_LAUNCH_LABELS = [
  { label: 'com.apple.smbd', service: 'File Sharing (SMB)' },
  { label: 'com.apple.AppleFileServer', service: 'File Sharing (AFP)' },
  { label: 'com.apple.screensharing', service: 'Screen Sharing' },
  { label: 'com.apple.RemoteDesktop.PrivilegeProxy', service: 'Remote Management' },
  { label: 'com.openssh.sshd', service: 'Remote Login (SSH)' },
];

async function isLaunchctlLoaded(label: string): Promise<boolean> {
  const result = await runCommand('launchctl', ['print-disabled', 'system']);
  const haystack = result.stdout + result.stderr;
  const disabledLine = new RegExp(`\\"${label.replaceAll('.', '\\\\.')}\\"\\s*=>\\s*disabled`, 'i');
  if (disabledLine.test(haystack)) return false;
  return haystack.includes(label);
}

function patternForEnabled(enabled: boolean): Pattern {
  return enabled ? 'yellow' : 'blue';
}

async function* scanSharingServices(): AsyncIterable<Finding> {
  for (const { label, service } of SHARING_LAUNCH_LABELS) {
    const enabled = await isLaunchctlLoaded(label);
    yield buildFinding({
      scannerId: SCANNER_ID,
      magi: 'melchior',
      pattern: patternForEnabled(enabled),
      title: `${service}: ${enabled ? 'enabled' : 'disabled'}`,
      evidence: `launchctl label: ${label}`,
      remediation:
        enabled && service !== 'Remote Login (SSH)'
          ? `Disable from System Settings → General → Sharing if not required.`
          : undefined,
    });
  }
}

export const sharingServicesScanner: Scanner = {
  id: SCANNER_ID,
  title: 'Sharing Services',
  magi: 'melchior',
  run: scanSharingServices,
};
