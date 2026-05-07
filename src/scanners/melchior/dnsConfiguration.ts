import { readFile } from 'node:fs/promises';
import { runCommand } from '../../core/shell.js';
import { buildFinding } from '../../core/finding.js';
import { maybeRedact } from '../../core/redact.js';
import type { Finding, ScanContext, Scanner } from '../../core/types.js';

const SCANNER_ID = 'melchior.dns-configuration';
const HOSTS_PATH = '/etc/hosts';

async function readResolvedDnsServers(): Promise<string> {
  const result = await runCommand('scutil', ['--dns']);
  return result.stdout.trim();
}

async function readHostsFile(): Promise<string> {
  try {
    return await readFile(HOSTS_PATH, 'utf8');
  } catch {
    return '';
  }
}

function isHostsFileVanilla(contents: string): boolean {
  const meaningful = contents
    .split('\n')
    .map((line) => line.trim())
    .filter((line) => line.length > 0 && !line.startsWith('#'));
  const baseline = new Set([
    '127.0.0.1\tlocalhost',
    '255.255.255.255\tbroadcasthost',
    '::1             localhost',
    'fe80::1%lo0\tlocalhost',
  ]);
  return meaningful.every((line) => baseline.has(line) || /^(127\.0\.0\.1|::1)\s+localhost$/.test(line));
}

async function* scanDnsConfiguration(context: ScanContext): AsyncIterable<Finding> {
  const [dnsConfig, hosts] = await Promise.all([readResolvedDnsServers(), readHostsFile()]);
  const customHosts = hosts.length > 0 && !isHostsFileVanilla(hosts);

  yield buildFinding({
    scannerId: SCANNER_ID,
    magi: 'melchior',
    pattern: 'blue',
    title: 'Resolved DNS configuration',
    evidence: maybeRedact(dnsConfig, context.redact),
  });

  yield buildFinding({
    scannerId: SCANNER_ID,
    magi: 'melchior',
    pattern: customHosts ? 'yellow' : 'blue',
    title: customHosts ? 'Custom /etc/hosts entries detected' : '/etc/hosts is unmodified',
    evidence: maybeRedact(hosts || '(empty)', context.redact),
    remediation: customHosts ? 'Verify entries; attackers commonly redirect domains via /etc/hosts.' : undefined,
  });
}

export const dnsConfigurationScanner: Scanner = {
  id: SCANNER_ID,
  title: 'DNS & Hosts',
  magi: 'melchior',
  run: scanDnsConfiguration,
};
