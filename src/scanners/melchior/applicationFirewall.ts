import { runCommand, commandFailed, commandUnavailable, describeFailure } from '../../core/shell.js';
import { buildFinding } from '../../core/finding.js';
import type { Finding, Scanner } from '../../core/types.js';

const SCANNER_ID = 'melchior.application-firewall';
const PRIMARY_PATH = '/usr/libexec/ApplicationFirewall/socketfilterfw';

async function runFirewall(args: string[]) {
  const primary = await runCommand(PRIMARY_PATH, args);
  if (!commandUnavailable(primary)) return primary;
  return runCommand('socketfilterfw', args);
}

function isEnabled(output: string): boolean {
  return /enabled/i.test(output) && !/disabled/i.test(output);
}

async function* scanApplicationFirewall(): AsyncIterable<Finding> {
  const [globalState, stealthMode] = await Promise.all([
    runFirewall(['--getglobalstate']),
    runFirewall(['--getstealthmode']),
  ]);

  if (commandUnavailable(globalState)) {
    yield buildFinding({
      scannerId: SCANNER_ID,
      magi: 'melchior',
      pattern: 'yellow',
      title: 'Application firewall CLI unavailable',
      evidence: describeFailure(globalState),
    });
    return;
  }

  const firewallOn = !commandFailed(globalState) && isEnabled(globalState.stdout);
  yield buildFinding({
    scannerId: SCANNER_ID,
    magi: 'melchior',
    pattern: firewallOn ? 'blue' : 'orange',
    title: firewallOn ? 'Application firewall is enabled' : 'Application firewall is DISABLED',
    evidence: globalState.stdout.trim() || describeFailure(globalState),
    remediation: firewallOn ? undefined : 'Enable under System Settings → Network → Firewall.',
  });

  const stealthOn = !commandFailed(stealthMode) && isEnabled(stealthMode.stdout);
  yield buildFinding({
    scannerId: SCANNER_ID,
    magi: 'melchior',
    pattern: stealthOn ? 'blue' : 'yellow',
    title: stealthOn ? 'Firewall stealth mode is enabled' : 'Firewall stealth mode is OFF',
    evidence: stealthMode.stdout.trim() || describeFailure(stealthMode),
    remediation: stealthOn
      ? undefined
      : 'Enable: sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setstealthmode on',
  });
}

export const applicationFirewallScanner: Scanner = {
  id: SCANNER_ID,
  title: 'Application Firewall',
  magi: 'melchior',
  run: scanApplicationFirewall,
};
