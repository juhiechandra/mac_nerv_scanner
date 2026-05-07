import { runAndCaptureLines } from '../../core/shell.js';
import { buildFinding } from '../../core/finding.js';
import { maybeRedact } from '../../core/redact.js';
import type { Finding, Pattern, ScanContext, Scanner } from '../../core/types.js';

const SCANNER_ID = 'melchior.listening-sockets';

const RISKY_PORTS = new Map<number, string>([
  [22, 'SSH'],
  [23, 'Telnet'],
  [445, 'SMB'],
  [548, 'AFP'],
  [873, 'rsync'],
  [3306, 'MySQL'],
  [3389, 'RDP'],
  [5432, 'PostgreSQL'],
  [5900, 'VNC'],
  [6379, 'Redis'],
  [11211, 'Memcached'],
  [27017, 'MongoDB'],
]);

function isRiskyPort(port: number): { risky: boolean; service?: string } {
  if (RISKY_PORTS.has(port)) return { risky: true, service: RISKY_PORTS.get(port) };
  if (port >= 6000 && port <= 6063) return { risky: true, service: 'X11' };
  return { risky: false };
}

interface ParsedSocket {
  raw: string;
  port: number | null;
  bindAddress: string | null;
  command: string | null;
}

function parseSocket(line: string): ParsedSocket {
  const cols = line.split(/\s+/);
  const command = cols[0] ?? null;
  const nameCol = cols[cols.length - 2] ?? '';
  const portMatch = nameCol.match(/:(\d+)$/);
  const bindMatch = nameCol.match(/^(.+):\d+$/);
  return {
    raw: line,
    port: portMatch ? Number(portMatch[1]) : null,
    bindAddress: bindMatch ? bindMatch[1] ?? null : null,
    command,
  };
}

function dropHeaderLine(lines: string[]): string[] {
  if (lines.length === 0) return lines;
  return /^COMMAND\b/i.test(lines[0] ?? '') ? lines.slice(1) : lines;
}

function bindIsExternal(bindAddress: string | null): boolean {
  if (!bindAddress) return false;
  if (bindAddress === '127.0.0.1' || bindAddress === '[::1]' || bindAddress === '*') return bindAddress === '*';
  return !bindAddress.startsWith('127.') && bindAddress !== '[::1]';
}

function severityFor(socket: ParsedSocket): { pattern: Pattern; reason: string | null } {
  if (socket.port === null) return { pattern: 'blue', reason: null };
  const { risky, service } = isRiskyPort(socket.port);
  if (!risky) return { pattern: 'blue', reason: null };
  const external = bindIsExternal(socket.bindAddress);
  if (external) return { pattern: 'orange', reason: `${service} bound to ${socket.bindAddress}` };
  return { pattern: 'yellow', reason: `${service} bound to localhost` };
}

async function* scanListeningSockets(context: ScanContext): AsyncIterable<Finding> {
  const lines = dropHeaderLine(await runAndCaptureLines('lsof', ['-nP', '-iTCP', '-sTCP:LISTEN']));

  if (lines.length === 0) {
    yield buildFinding({
      scannerId: SCANNER_ID,
      magi: 'melchior',
      pattern: 'blue',
      title: 'No listening TCP sockets',
      evidence: 'lsof reports no LISTEN-state sockets.',
    });
    return;
  }

  const sockets = lines.map(parseSocket);

  yield buildFinding({
    scannerId: SCANNER_ID,
    magi: 'melchior',
    pattern: 'blue',
    title: `${sockets.length} TCP socket(s) in LISTEN state`,
    evidence: maybeRedact(lines.join('\n'), context.redact),
  });

  const flagged = sockets
    .map((s) => ({ socket: s, ...severityFor(s) }))
    .filter((entry) => entry.reason !== null);

  for (const entry of flagged) {
    yield buildFinding({
      scannerId: SCANNER_ID,
      magi: 'melchior',
      pattern: entry.pattern,
      title: `Risky listener: ${entry.reason}`,
      evidence: maybeRedact(entry.socket.raw, context.redact),
      remediation:
        entry.pattern === 'orange'
          ? `Confirm ${entry.socket.command ?? 'this process'} should be reachable on the network; bind to 127.0.0.1 if not.`
          : `Verify ${entry.socket.command ?? 'this process'} should be running.`,
    });
  }
}

export const listeningSocketsScanner: Scanner = {
  id: SCANNER_ID,
  title: 'Listening Sockets',
  magi: 'melchior',
  run: scanListeningSockets,
};
