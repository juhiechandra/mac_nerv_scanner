import { readFile } from 'node:fs/promises';
import { runCommand } from '../../core/shell.js';
import { buildFinding } from '../../core/finding.js';
import { maybeRedact } from '../../core/redact.js';
import type { Finding, Pattern, ScanContext, Scanner } from '../../core/types.js';

const SCANNER_ID = 'melchior.dns-configuration';
const HOSTS_PATH = '/etc/hosts';

const SENSITIVE_DOMAINS = [
  'apple.com',
  'icloud.com',
  'github.com',
  'google.com',
  'microsoft.com',
  'amazon.com',
  'cloudflare.com',
  'live.com',
];

const KNOWN_PUBLIC_RESOLVERS = new Set([
  '1.1.1.1',
  '1.0.0.1',
  '8.8.8.8',
  '8.8.4.4',
  '9.9.9.9',
  '149.112.112.112',
  '208.67.222.222',
  '208.67.220.220',
]);

async function readResolvers(): Promise<{ raw: string; servers: string[] }> {
  const result = await runCommand('scutil', ['--dns']);
  const raw = result.stdout.trim();
  const servers = Array.from(raw.matchAll(/nameserver\[\d+\]\s*:\s*([0-9.a-fA-F:]+)/g))
    .map((match) => match[1] ?? '')
    .filter((value) => value.length > 0);
  return { raw, servers: Array.from(new Set(servers)) };
}

async function readHostsFile(): Promise<string> {
  try {
    return await readFile(HOSTS_PATH, 'utf8');
  } catch {
    return '';
  }
}

function isPrivateOrLoopback(ip: string): boolean {
  if (ip === '127.0.0.1' || ip === '::1') return true;
  if (ip.startsWith('10.')) return true;
  if (ip.startsWith('192.168.')) return true;
  const m = ip.match(/^172\.(\d+)\./);
  if (m && Number(m[1]) >= 16 && Number(m[1]) <= 31) return true;
  if (ip.startsWith('fe80:') || ip.startsWith('fc') || ip.startsWith('fd')) return true;
  return false;
}

function classifyResolvers(servers: string[]): { pattern: Pattern; reason: string } {
  const unknown = servers.filter((s) => !isPrivateOrLoopback(s) && !KNOWN_PUBLIC_RESOLVERS.has(s));
  if (unknown.length === 0) return { pattern: 'blue', reason: 'all resolvers are private or well-known public' };
  return {
    pattern: 'yellow',
    reason: `unknown public resolver(s): ${unknown.join(', ')}`,
  };
}

function vanillaHostLine(line: string): boolean {
  if (line.length === 0 || line.startsWith('#')) return true;
  return /^(127\.0\.0\.1|::1|fe80::1%lo0|255\.255\.255\.255)\s+\S+$/.test(line);
}

function findRedirects(hosts: string): string[] {
  return hosts
    .split('\n')
    .map((line) => line.trim())
    .filter((line) => line.length > 0 && !line.startsWith('#'))
    .filter((line) => SENSITIVE_DOMAINS.some((domain) => line.toLowerCase().includes(domain)));
}

async function* scanDnsConfiguration(context: ScanContext): AsyncIterable<Finding> {
  const [{ raw, servers }, hosts] = await Promise.all([readResolvers(), readHostsFile()]);

  const { pattern: resolverPattern, reason } = classifyResolvers(servers);
  yield buildFinding({
    scannerId: SCANNER_ID,
    magi: 'melchior',
    pattern: resolverPattern,
    title: `DNS resolvers: ${reason}`,
    evidence: maybeRedact(raw || '(no scutil data)', context.redact),
    remediation:
      resolverPattern === 'yellow'
        ? 'Verify these resolvers are intentional (corporate/VPN). Unknown resolvers can MITM all DNS.'
        : undefined,
  });

  const meaningful = hosts.split('\n').map((l) => l.trim()).filter((l) => !vanillaHostLine(l));
  const redirects = findRedirects(hosts);
  let pattern: Pattern = 'blue';
  let title = '/etc/hosts is unmodified';
  if (redirects.length > 0) {
    pattern = 'orange';
    title = `/etc/hosts redirects sensitive domain(s): ${redirects.length}`;
  } else if (meaningful.length > 0) {
    pattern = 'yellow';
    title = `Custom /etc/hosts entries: ${meaningful.length}`;
  }

  yield buildFinding({
    scannerId: SCANNER_ID,
    magi: 'melchior',
    pattern,
    title,
    evidence: maybeRedact(hosts || '(empty)', context.redact),
    remediation:
      pattern === 'orange'
        ? 'Investigate redirects to apple.com / icloud.com / github.com — these are common phishing/MITM targets.'
        : pattern === 'yellow'
          ? 'Verify each non-default entry; attackers commonly redirect domains via /etc/hosts.'
          : undefined,
  });
}

export const dnsConfigurationScanner: Scanner = {
  id: SCANNER_ID,
  title: 'DNS & Hosts',
  magi: 'melchior',
  run: scanDnsConfiguration,
};
