import { runCommand } from '../../core/shell.js';
import { buildFinding } from '../../core/finding.js';
import type { Finding, Scanner } from '../../core/types.js';

const SCANNER_ID = 'melchior.user-trusted-certs';

async function readUserAddedCertificates(): Promise<string> {
  const result = await runCommand('security', ['dump-trust-settings']);
  return (result.stdout + result.stderr).trim();
}

function hasUserTrustOverrides(output: string): boolean {
  return /Cert\s+\d+:/i.test(output);
}

async function* scanUserTrustedCertificates(): AsyncIterable<Finding> {
  const dump = await readUserAddedCertificates();
  const overrides = hasUserTrustOverrides(dump);
  yield buildFinding({
    scannerId: SCANNER_ID,
    magi: 'melchior',
    pattern: overrides ? 'yellow' : 'blue',
    title: overrides ? 'User-level trust overrides detected' : 'No user-level trust overrides',
    evidence: dump || 'No user-added trust settings.',
    remediation: overrides ? 'Review each entry in Keychain Access → System Roots; remove unknown CAs.' : undefined,
  });
}

export const userTrustedCertificatesScanner: Scanner = {
  id: SCANNER_ID,
  title: 'User-Trusted Certificates',
  magi: 'melchior',
  run: scanUserTrustedCertificates,
};
