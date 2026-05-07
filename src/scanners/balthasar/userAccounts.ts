import { runAndCaptureLines, runCommand } from '../../core/shell.js';
import { buildFinding } from '../../core/finding.js';
import { maybeRedact } from '../../core/redact.js';
import type { Finding, ScanContext, Scanner } from '../../core/types.js';

const SCANNER_ID = 'balthasar.user-accounts';

async function listAdminMembers(): Promise<string[]> {
  const lines = await runAndCaptureLines('dscl', ['.', '-read', '/Groups/admin', 'GroupMembership']);
  const header = lines.find((line) => line.startsWith('GroupMembership:')) ?? '';
  return header
    .replace('GroupMembership:', '')
    .trim()
    .split(/\s+/)
    .filter((entry) => entry.length > 0);
}

async function listLocalUsers(): Promise<string[]> {
  const lines = await runAndCaptureLines('dscl', ['.', '-list', '/Users']);
  return lines.filter((line) => !line.startsWith('_') && !['daemon', 'nobody', 'root'].includes(line));
}

async function rootIsEnabled(): Promise<{ enabled: boolean; evidence: string }> {
  const result = await runCommand('dscl', ['.', '-read', '/Users/root', 'AuthenticationAuthority']);
  if (result.exitCode !== 0) {
    return { enabled: false, evidence: 'AuthenticationAuthority unreadable (likely disabled).' };
  }
  const output = result.stdout.trim();
  const hasShadowHash = /ShadowHash/i.test(output);
  return { enabled: hasShadowHash, evidence: output || '(empty)' };
}

async function readGuestEnabled(): Promise<{ enabled: boolean; evidence: string }> {
  const result = await runCommand('defaults', [
    'read',
    '/Library/Preferences/com.apple.loginwindow',
    'GuestEnabled',
  ]);
  if (result.exitCode !== 0) {
    return { enabled: false, evidence: 'GuestEnabled key not set (default: off).' };
  }
  const value = result.stdout.trim();
  return { enabled: value === '1', evidence: `GuestEnabled=${value}` };
}

async function autoLoginUser(): Promise<string | null> {
  const result = await runCommand('defaults', [
    'read',
    '/Library/Preferences/com.apple.loginwindow',
    'autoLoginUser',
  ]);
  if (result.exitCode !== 0) return null;
  const value = result.stdout.trim();
  return value.length > 0 ? value : null;
}

async function* scanUserAccounts(context: ScanContext): AsyncIterable<Finding> {
  const [admins, users, root, guest, autoLogin] = await Promise.all([
    listAdminMembers(),
    listLocalUsers(),
    rootIsEnabled(),
    readGuestEnabled(),
    autoLoginUser(),
  ]);

  yield buildFinding({
    scannerId: SCANNER_ID,
    magi: 'balthasar',
    pattern: admins.length > 1 ? 'yellow' : 'blue',
    title: `${admins.length} admin account(s)`,
    evidence: maybeRedact(admins.join(', ') || '(none)', context.redact),
    remediation:
      admins.length > 1
        ? 'Reduce admin count to the minimum needed; demote the rest to standard users.'
        : undefined,
  });

  yield buildFinding({
    scannerId: SCANNER_ID,
    magi: 'balthasar',
    pattern: 'blue',
    title: `${users.length} non-system local user account(s)`,
    evidence: maybeRedact(users.join('\n') || '(none)', context.redact),
  });

  yield buildFinding({
    scannerId: SCANNER_ID,
    magi: 'balthasar',
    pattern: root.enabled ? 'red' : 'blue',
    title: root.enabled ? 'root account is ENABLED' : 'root account is disabled',
    evidence: root.evidence,
    remediation: root.enabled
      ? 'Disable: dsenableroot -d (root logins are a major lateral-movement risk).'
      : undefined,
  });

  yield buildFinding({
    scannerId: SCANNER_ID,
    magi: 'balthasar',
    pattern: guest.enabled ? 'orange' : 'blue',
    title: guest.enabled ? 'Guest account is ENABLED' : 'Guest account is disabled',
    evidence: guest.evidence,
    remediation: guest.enabled
      ? 'Disable under System Settings → Users & Groups → Guest User.'
      : undefined,
  });

  yield buildFinding({
    scannerId: SCANNER_ID,
    magi: 'balthasar',
    pattern: autoLogin ? 'orange' : 'blue',
    title: autoLogin ? `Auto-login enabled for user` : 'Auto-login is disabled',
    evidence: autoLogin ? maybeRedact(`autoLoginUser=${autoLogin}`, context.redact) : '(no autoLoginUser key)',
    remediation: autoLogin
      ? 'Disable under System Settings → Users & Groups → Login Options. Auto-login defeats FileVault.'
      : undefined,
  });
}

export const userAccountsScanner: Scanner = {
  id: SCANNER_ID,
  title: 'User Accounts',
  magi: 'balthasar',
  run: scanUserAccounts,
};
