import { runAndCaptureLines } from '../../core/shell.js';
import { buildFinding } from '../../core/finding.js';
import { maybeRedact } from '../../core/redact.js';
import type { Finding, ScanContext, Scanner } from '../../core/types.js';

const SCANNER_ID = 'balthasar.user-accounts';

async function listAdminMembers(): Promise<string[]> {
  const lines = await runAndCaptureLines('dscl', ['.', '-read', '/Groups/admin', 'GroupMembership']);
  const header = lines.find((line) => line.startsWith('GroupMembership:')) ?? '';
  return header.replace('GroupMembership:', '').trim().split(/\s+/).filter(Boolean);
}

async function listLocalUsers(): Promise<string[]> {
  const lines = await runAndCaptureLines('dscl', ['.', '-list', '/Users']);
  return lines.filter((line) => !line.startsWith('_') && line !== 'daemon' && line !== 'nobody' && line !== 'root');
}

async function* scanUserAccounts(context: ScanContext): AsyncIterable<Finding> {
  const [admins, users] = await Promise.all([listAdminMembers(), listLocalUsers()]);

  yield buildFinding({
    scannerId: SCANNER_ID,
    magi: 'balthasar',
    pattern: admins.length > 1 ? 'yellow' : 'blue',
    title: `${admins.length} admin account(s)`,
    evidence: maybeRedact(admins.join(', ') || '(none)', context.redact),
    remediation: admins.length > 1 ? 'Reduce admin count to the minimum needed; demote the rest to standard users.' : undefined,
  });

  yield buildFinding({
    scannerId: SCANNER_ID,
    magi: 'balthasar',
    pattern: 'blue',
    title: `${users.length} non-system local user account(s)`,
    evidence: maybeRedact(users.join('\n'), context.redact),
  });
}

export const userAccountsScanner: Scanner = {
  id: SCANNER_ID,
  title: 'User Accounts',
  magi: 'balthasar',
  run: scanUserAccounts,
};
