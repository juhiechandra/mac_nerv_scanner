import { runCommand, commandUnavailable, describeFailure } from '../../core/shell.js';
import { buildFinding } from '../../core/finding.js';
import type { Finding, Scanner } from '../../core/types.js';

const SCANNER_ID = 'casper.kernel-extensions';

const VENDOR_PREFIXES = ['com.apple.', 'com.amd.', 'com.nvidia.', 'com.intel.'];

interface KextSource {
  source: 'kmutil' | 'kextstat' | 'unavailable';
  lines: string[];
  failureReason?: string;
}

function splitLines(text: string): string[] {
  return text
    .split('\n')
    .map((line) => line.trim())
    .filter((line) => line.length > 0);
}

async function listLoadedKexts(): Promise<KextSource> {
  const kmutil = await runCommand('kmutil', ['showloaded', '--list-only'], { timeoutMs: 10000 });
  if (kmutil.exitCode === 0) {
    return { source: 'kmutil', lines: splitLines(kmutil.stdout) };
  }
  if (!commandUnavailable(kmutil) && kmutil.stdout.trim().length > 0) {
    return { source: 'kmutil', lines: splitLines(kmutil.stdout) };
  }
  const kextstat = await runCommand('kextstat', ['-kl'], { timeoutMs: 10000 });
  if (kextstat.exitCode === 0) {
    return { source: 'kextstat', lines: splitLines(kextstat.stdout) };
  }
  return { source: 'unavailable', lines: [], failureReason: describeFailure(kextstat) };
}

function isVendorSigned(line: string): boolean {
  const lowered = line.toLowerCase();
  return VENDOR_PREFIXES.some((prefix) => lowered.includes(prefix));
}

function partitionKexts(lines: string[]): { thirdParty: string[]; total: number } {
  const thirdParty = lines.filter((line) => !isVendorSigned(line));
  return { thirdParty, total: lines.length };
}

async function* scanKernelExtensions(): AsyncIterable<Finding> {
  const result = await listLoadedKexts();

  if (result.source === 'unavailable') {
    yield buildFinding({
      scannerId: SCANNER_ID,
      magi: 'casper',
      pattern: 'yellow',
      title: 'Kernel extension list unavailable',
      evidence: result.failureReason ?? 'kmutil and kextstat both failed',
      remediation: 'Install Command Line Tools (xcode-select --install) so kmutil/kextstat are available.',
    });
    return;
  }

  const { thirdParty, total } = partitionKexts(result.lines);

  if (thirdParty.length === 0) {
    yield buildFinding({
      scannerId: SCANNER_ID,
      magi: 'casper',
      pattern: 'blue',
      title: `${total} vendor-signed kernel extensions loaded (via ${result.source})`,
      evidence: 'No third-party kernel extensions detected.',
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
