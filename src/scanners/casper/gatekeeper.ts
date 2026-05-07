import { runCommand, commandFailed, describeFailure } from '../../core/shell.js';
import { buildFinding } from '../../core/finding.js';
import type { Finding, Scanner } from '../../core/types.js';

const SCANNER_ID = 'casper.gatekeeper';

async function* scanGatekeeper(): AsyncIterable<Finding> {
  const result = await runCommand('spctl', ['--status']);

  if (commandFailed(result)) {
    yield buildFinding({
      scannerId: SCANNER_ID,
      magi: 'casper',
      pattern: 'yellow',
      title: 'Gatekeeper status unavailable',
      evidence: describeFailure(result),
    });
    return;
  }

  const status = result.stdout.trim();
  const enabled = /assessments enabled/i.test(status);

  yield buildFinding({
    scannerId: SCANNER_ID,
    magi: 'casper',
    pattern: enabled ? 'blue' : 'orange',
    title: enabled ? 'Gatekeeper assessments are enabled' : 'Gatekeeper assessments are DISABLED',
    evidence: status || 'spctl returned no output',
    remediation: enabled ? undefined : 'Re-enable: sudo spctl --master-enable',
    references: ['https://support.apple.com/en-us/HT202491'],
  });
}

export const gatekeeperScanner: Scanner = {
  id: SCANNER_ID,
  title: 'Gatekeeper',
  magi: 'casper',
  run: scanGatekeeper,
};
