import { runCommand } from '../../core/shell.js';
import { buildFinding } from '../../core/finding.js';
import type { Finding, Scanner } from '../../core/types.js';

const SCANNER_ID = 'casper.gatekeeper';

async function readAssessmentState(): Promise<string> {
  const result = await runCommand('spctl', ['--status']);
  return (result.stdout + result.stderr).trim();
}

function isAssessmentEnabled(output: string): boolean {
  return /assessments enabled/i.test(output);
}

async function* scanGatekeeper(): AsyncIterable<Finding> {
  const status = await readAssessmentState();
  const enabled = isAssessmentEnabled(status);
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
