import { runCommand, commandFailed, describeFailure } from '../../core/shell.js';
import { buildFinding } from '../../core/finding.js';
import type { Finding, Scanner } from '../../core/types.js';

const SCANNER_ID = 'melchior.user-trusted-certs';

async function* scanUserTrustedCertificates(): AsyncIterable<Finding> {
  const result = await runCommand('security', ['dump-trust-settings']);

  if (commandFailed(result) && result.stdout.trim().length === 0) {
    yield buildFinding({
      scannerId: SCANNER_ID,
      magi: 'melchior',
      pattern: 'yellow',
      title: 'User trust settings unavailable',
      evidence: describeFailure(result),
    });
    return;
  }

  const dump = result.stdout.trim();
  const certCount = (dump.match(/^Cert\s+\d+:/gim) ?? []).length;

  yield buildFinding({
    scannerId: SCANNER_ID,
    magi: 'melchior',
    pattern: certCount > 0 ? 'yellow' : 'blue',
    title: certCount > 0 ? `${certCount} user-level trust override(s)` : 'No user-level trust overrides',
    evidence: dump || 'No user-added trust settings.',
    remediation: certCount > 0 ? 'Review each entry in Keychain Access → System Roots; remove unknown CAs.' : undefined,
  });
}

export const userTrustedCertificatesScanner: Scanner = {
  id: SCANNER_ID,
  title: 'User-Trusted Certificates',
  magi: 'melchior',
  run: scanUserTrustedCertificates,
};
