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

async function isServiceLoaded(label: string): Promise<{ loaded: boolean; evidence: string }> {
  const result = await runCommand('launchctl', ['print', `system/${label}`]);
  if (result.exitCode === 0) {
    return { loaded: true, evidence: `launchctl print system/${label} → loaded` };
  }
  if (/could not find service/i.test(result.stderr)) {
    return { loaded: false, evidence: `launchctl print system/${label} → not loaded` };
  }
  return { loaded: false, evidence: result.stderr.trim() || `exit ${result.exitCode}` };
}

function patternForEnabled(enabled: boolean): Pattern {
  return enabled ? 'yellow' : 'blue';
}

async function* scanSharingServices(): AsyncIterable<Finding> {
  for (const { label, service } of SHARING_LAUNCH_LABELS) {
    const { loaded, evidence } = await isServiceLoaded(label);
    yield buildFinding({
      scannerId: SCANNER_ID,
      magi: 'melchior',
      pattern: patternForEnabled(loaded),
      title: `${service}: ${loaded ? 'enabled' : 'disabled'}`,
      evidence,
      remediation: loaded
        ? `Disable from System Settings → General → Sharing if not required (label: ${label}).`
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
