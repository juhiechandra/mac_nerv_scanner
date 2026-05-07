import { readdir, readFile, stat } from 'node:fs/promises';
import { homedir } from 'node:os';
import { join } from 'node:path';
import { buildFinding } from '../../core/finding.js';
import { maybeRedact } from '../../core/redact.js';
import type { Finding, ScanContext, Scanner } from '../../core/types.js';

const SCANNER_ID = 'balthasar.ssh';

async function listSshKeys(): Promise<string[]> {
  const sshDir = join(homedir(), '.ssh');
  try {
    const entries = await readdir(sshDir);
    return entries.filter((entry) => entry.endsWith('.pub') || entry.startsWith('id_'));
  } catch {
    return [];
  }
}

async function readAuthorizedKeys(): Promise<string> {
  const path = join(homedir(), '.ssh', 'authorized_keys');
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

async function* scanSshConfiguration(context: ScanContext): AsyncIterable<Finding> {
  const [keys, authorized] = await Promise.all([listSshKeys(), readAuthorizedKeys()]);
  const authorizedCount = countAuthorizedKeys(authorized);

  yield buildFinding({
    scannerId: SCANNER_ID,
    magi: 'balthasar',
    pattern: 'blue',
    title: `${keys.length} SSH key file(s) in ~/.ssh`,
    evidence: maybeRedact(keys.join('\n') || '(none)', context.redact),
  });

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
}

export const sshConfigurationScanner: Scanner = {
  id: SCANNER_ID,
  title: 'SSH Configuration',
  magi: 'balthasar',
  run: scanSshConfiguration,
};
