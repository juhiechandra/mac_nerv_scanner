import { readdir, readFile, stat } from 'node:fs/promises';
import { homedir } from 'node:os';
import { join } from 'node:path';
import { runCommand } from '../../core/shell.js';
import { buildFinding } from '../../core/finding.js';
import { maybeRedact } from '../../core/redact.js';
import type { Finding, Pattern, ScanContext, Scanner } from '../../core/types.js';

const SCANNER_ID = 'balthasar.ssh';

interface ParsedKey {
  file: string;
  bits: number | null;
  type: string | null;
  raw: string;
}

async function listPublicKeys(sshDir: string): Promise<string[]> {
  try {
    const entries = await readdir(sshDir);
    return entries
      .filter((entry) => entry.endsWith('.pub'))
      .map((entry) => join(sshDir, entry));
  } catch {
    return [];
  }
}

async function parsePublicKey(filePath: string): Promise<ParsedKey> {
  const result = await runCommand('ssh-keygen', ['-lf', filePath]);
  if (result.exitCode !== 0) {
    return { file: filePath, bits: null, type: null, raw: result.stderr.trim() || result.stdout.trim() };
  }
  const line = result.stdout.trim();
  const match = line.match(/^(\d+)\s+\S+\s+\S+(?:.*?)\((\w+)\)$/);
  return {
    file: filePath,
    bits: match ? Number(match[1]) : null,
    type: match ? match[2] ?? null : null,
    raw: line,
  };
}

function classifyKey(key: ParsedKey): Pattern {
  if (!key.type) return 'yellow';
  const type = key.type.toUpperCase();
  if (type === 'DSA') return 'red';
  if (type === 'RSA' && key.bits !== null && key.bits < 3072) return 'yellow';
  return 'blue';
}

async function readAuthorizedKeys(sshDir: string): Promise<string> {
  const path = join(sshDir, 'authorized_keys');
  try {
    const stats = await stat(path);
    if (!stats.isFile()) return '';
    return await readFile(path, 'utf8');
  } catch {
    return '';
  }
}

function countAuthorizedKeys(contents: string): number {
  return contents
    .split('\n')
    .map((line) => line.trim())
    .filter((line) => line.length > 0 && !line.startsWith('#')).length;
}

async function readSshConfig(sshDir: string): Promise<string> {
  try {
    return await readFile(join(sshDir, 'config'), 'utf8');
  } catch {
    return '';
  }
}

function findProxyDirectives(config: string): string[] {
  return config
    .split('\n')
    .map((line) => line.trim())
    .filter((line) => /^Proxy(Command|Jump)\b/i.test(line));
}

async function readRemoteLogin(): Promise<{ enabled: boolean | null; evidence: string }> {
  const result = await runCommand('systemsetup', ['-getremotelogin']);
  if (result.exitCode !== 0) {
    return { enabled: null, evidence: result.stderr.trim() || 'systemsetup -getremotelogin needs admin' };
  }
  const text = result.stdout.trim();
  if (/Remote Login:\s*On/i.test(text)) return { enabled: true, evidence: text };
  if (/Remote Login:\s*Off/i.test(text)) return { enabled: false, evidence: text };
  return { enabled: null, evidence: text };
}

async function* scanSshConfiguration(context: ScanContext): AsyncIterable<Finding> {
  const sshDir = join(homedir(), '.ssh');
  const [pubKeyPaths, authorized, sshConfig, remoteLogin] = await Promise.all([
    listPublicKeys(sshDir),
    readAuthorizedKeys(sshDir),
    readSshConfig(sshDir),
    readRemoteLogin(),
  ]);

  if (remoteLogin.enabled !== null) {
    yield buildFinding({
      scannerId: SCANNER_ID,
      magi: 'balthasar',
      pattern: remoteLogin.enabled ? 'orange' : 'blue',
      title: remoteLogin.enabled ? 'Remote Login (sshd) is ENABLED' : 'Remote Login (sshd) is disabled',
      evidence: remoteLogin.evidence,
      remediation: remoteLogin.enabled
        ? 'Disable: sudo systemsetup -setremotelogin off (or System Settings → General → Sharing → Remote Login).'
        : undefined,
    });
  }

  const parsedKeys = await Promise.all(pubKeyPaths.map(parsePublicKey));
  yield buildFinding({
    scannerId: SCANNER_ID,
    magi: 'balthasar',
    pattern: 'blue',
    title: `${parsedKeys.length} SSH public key(s) in ~/.ssh`,
    evidence:
      parsedKeys.length === 0
        ? '(none)'
        : maybeRedact(parsedKeys.map((k) => k.raw).join('\n'), context.redact),
  });

  for (const key of parsedKeys) {
    const pattern = classifyKey(key);
    if (pattern === 'blue') continue;
    yield buildFinding({
      scannerId: SCANNER_ID,
      magi: 'balthasar',
      pattern,
      title:
        pattern === 'red'
          ? `Weak SSH key (DSA): ${key.file}`
          : `Weak SSH key (${key.type ?? '?'}/${key.bits ?? '?'} bits): ${key.file}`,
      evidence: maybeRedact(key.raw, context.redact),
      remediation:
        pattern === 'red'
          ? 'DSA is broken — generate a new ED25519 key: ssh-keygen -t ed25519'
          : 'Generate a stronger key: ssh-keygen -t ed25519 (or RSA ≥ 4096).',
    });
  }

  const authorizedCount = countAuthorizedKeys(authorized);
  yield buildFinding({
    scannerId: SCANNER_ID,
    magi: 'balthasar',
    pattern: authorizedCount > 0 ? 'yellow' : 'blue',
    title: `${authorizedCount} authorized_keys entr${authorizedCount === 1 ? 'y' : 'ies'}`,
    evidence: maybeRedact(authorized || '(empty)', context.redact),
    remediation:
      authorizedCount > 0
        ? 'Each entry grants remote shell access; remove anything you do not recognise.'
        : undefined,
  });

  const proxies = findProxyDirectives(sshConfig);
  if (proxies.length > 0) {
    yield buildFinding({
      scannerId: SCANNER_ID,
      magi: 'balthasar',
      pattern: 'yellow',
      title: `${proxies.length} ProxyCommand/ProxyJump directive(s) in ~/.ssh/config`,
      evidence: maybeRedact(proxies.join('\n'), context.redact),
      remediation:
        'Verify each proxy host is trusted; ProxyCommand can be abused to MITM your SSH sessions.',
    });
  }
}

export const sshConfigurationScanner: Scanner = {
  id: SCANNER_ID,
  title: 'SSH Configuration',
  magi: 'balthasar',
  run: scanSshConfiguration,
};
