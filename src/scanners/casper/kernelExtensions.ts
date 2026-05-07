import { runAndCaptureLines } from '../../core/shell.js';
import { buildFinding } from '../../core/finding.js';
import type { Finding, Scanner } from '../../core/types.js';

const SCANNER_ID = 'casper.kernel-extensions';

async function listLoadedKexts(): Promise<string[]> {
  return runAndCaptureLines('kmutil', ['showloaded', '--list-only']);
}

function isAppleSigned(line: string): boolean {
  return /com\.apple\./.test(line);
}

function summarizeThirdParty(kexts: string[]): { thirdParty: string[]; total: number } {
  const thirdParty = kexts.filter((line) => !isAppleSigned(line) && line.length > 0);
  return { thirdParty, total: kexts.length };
}

async function* scanKernelExtensions(): AsyncIterable<Finding> {
  const kexts = await listLoadedKexts();
  const { thirdParty, total } = summarizeThirdParty(kexts);

  if (thirdParty.length === 0) {
    yield buildFinding({
      scannerId: SCANNER_ID,
      magi: 'casper',
      pattern: 'blue',
      title: `${total} Apple-signed kernel extensions loaded`,
      evidence: `No third-party kernel extensions detected.`,
    });
    return;
  }

  yield buildFinding({
    scannerId: SCANNER_ID,
    magi: 'casper',
    pattern: 'yellow',
    title: `${thirdParty.length} third-party kernel extension(s) loaded`,
    evidence: thirdParty.join('\n'),
    remediation: 'Verify each third-party kext is from a trusted vendor; remove unknown ones.',
  });
}

export const kernelExtensionsScanner: Scanner = {
  id: SCANNER_ID,
  title: 'Kernel Extensions',
  magi: 'casper',
  run: scanKernelExtensions,
};
