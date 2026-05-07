import { runCommand } from '../../core/shell.js';
import { buildFinding } from '../../core/finding.js';
import type { Finding, Scanner } from '../../core/types.js';

const SCANNER_ID = 'melchior.application-firewall';
const FIREWALL_CLI = '/usr/libexec/ApplicationFirewall/socketfilterfw';

async function readGlobalState(): Promise<string> {
  const result = await runCommand(FIREWALL_CLI, ['--getglobalstate']);
  return (result.stdout + result.stderr).trim();
}

async function readStealthMode(): Promise<string> {
  const result = await runCommand(FIREWALL_CLI, ['--getstealthmode']);
  return (result.stdout + result.stderr).trim();
}

function isFirewallEnabled(output: string): boolean {
  return /enabled/i.test(output);
}

async function* scanApplicationFirewall(): AsyncIterable<Finding> {
  const [globalState, stealthMode] = await Promise.all([readGlobalState(), readStealthMode()]);
  const firewallOn = isFirewallEnabled(globalState);
  yield buildFinding({
    scannerId: SCANNER_ID,
    magi: 'melchior',
    pattern: firewallOn ? 'blue' : 'orange',
    title: firewallOn ? 'Application firewall is enabled' : 'Application firewall is DISABLED',
    evidence: `${globalState}\n${stealthMode}`,
    remediation: firewallOn ? undefined : 'Enable under System Settings → Network → Firewall.',
  });
}

export const applicationFirewallScanner: Scanner = {
  id: SCANNER_ID,
  title: 'Application Firewall',
  magi: 'melchior',
  run: scanApplicationFirewall,
};
