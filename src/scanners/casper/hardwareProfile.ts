import { runCommand } from '../../core/shell.js';
import { buildFinding } from '../../core/finding.js';
import { maybeRedact } from '../../core/redact.js';
import type { Finding, ScanContext, Scanner } from '../../core/types.js';

const SCANNER_ID = 'casper.hardware-profile';

async function readHardwareSection(): Promise<string> {
  const result = await runCommand('system_profiler', ['SPHardwareDataType', '-detailLevel', 'mini']);
  return result.stdout.trim();
}

async function* scanHardwareProfile(context: ScanContext): AsyncIterable<Finding> {
  const profile = await readHardwareSection();
  if (profile.length === 0) {
    yield buildFinding({
      scannerId: SCANNER_ID,
      magi: 'casper',
      pattern: 'yellow',
      title: 'Hardware profile unavailable',
      evidence: 'system_profiler returned no data',
    });
    return;
  }

  yield buildFinding({
    scannerId: SCANNER_ID,
    magi: 'casper',
    pattern: 'blue',
    title: 'Hardware profile captured',
    evidence: maybeRedact(profile, context.redact),
  });
}

export const hardwareProfileScanner: Scanner = {
  id: SCANNER_ID,
  title: 'Hardware Profile',
  magi: 'casper',
  run: scanHardwareProfile,
};
