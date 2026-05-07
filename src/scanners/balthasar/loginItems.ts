import { readdir } from 'node:fs/promises';
import { homedir } from 'node:os';
import { join } from 'node:path';
import { runCommand } from '../../core/shell.js';
import { buildFinding } from '../../core/finding.js';
import { maybeRedact } from '../../core/redact.js';
import type { Finding, ScanContext, Scanner } from '../../core/types.js';

const SCANNER_ID = 'balthasar.login-items';

interface OsascriptOutcome {
  ok: boolean;
  permissionDenied: boolean;
  raw: string;
  items: string[];
}

async function readLoginItemsViaOsascript(): Promise<OsascriptOutcome> {
  const result = await runCommand('osascript', [
    '-e',
    'tell application "System Events" to get the name of every login item',
  ]);
  const stderr = result.stderr.trim();
  const stdout = result.stdout.trim();
  const permissionDenied = /\(-1743\)|not authorized|not allowed assistive access/i.test(stderr);
  if (result.exitCode !== 0 || permissionDenied || /execution error/i.test(stderr)) {
    return { ok: false, permissionDenied, raw: stderr || stdout, items: [] };
  }
  const items = stdout
    .split(',')
    .map((entry) => entry.trim())
    .filter((entry) => entry.length > 0);
  return { ok: true, permissionDenied: false, raw: stdout, items };
}

async function findBtmFile(): Promise<string | null> {
  const dir = join(homedir(), 'Library', 'Application Support', 'com.apple.backgroundtaskmanagementagent');
  try {
    const entries = await readdir(dir);
    const match = entries.find((entry) => /^BackgroundItems-v\d+\.btm$/.test(entry));
    return match ? join(dir, match) : null;
  } catch {
    return null;
  }
}

async function readBtmDump(path: string): Promise<string | null> {
  const result = await runCommand('plutil', ['-convert', 'json', '-o', '-', path]);
  if (result.exitCode !== 0) return null;
  return result.stdout;
}

function extractBtmIdentifiers(json: string): string[] {
  const ids = new Set<string>();
  for (const match of json.matchAll(/"(?:bundleIdentifier|identifier)"\s*:\s*"([^"]+)"/g)) {
    if (match[1]) ids.add(match[1]);
  }
  return Array.from(ids);
}

async function* scanLoginItems(context: ScanContext): AsyncIterable<Finding> {
  const osa = await readLoginItemsViaOsascript();

  if (osa.ok) {
    yield buildFinding({
      scannerId: SCANNER_ID,
      magi: 'balthasar',
      pattern: osa.items.length > 8 ? 'yellow' : 'blue',
      title: `${osa.items.length} login item(s) (osascript)`,
      evidence: maybeRedact(osa.items.length === 0 ? '(none)' : osa.items.join('\n'), context.redact),
      remediation:
        osa.items.length > 0
          ? 'Audit System Settings → General → Login Items; persistence injected here runs at every login.'
          : undefined,
    });
    return;
  }

  if (osa.permissionDenied) {
    yield buildFinding({
      scannerId: SCANNER_ID,
      magi: 'balthasar',
      pattern: 'yellow',
      title: 'Login items query needs Automation permission',
      evidence: osa.raw || 'osascript was denied automation access.',
      remediation:
        'Grant Terminal (or your terminal of choice) "Control System Events" under System Settings → Privacy & Security → Automation.',
    });
  }

  const btmPath = await findBtmFile();
  if (!btmPath) {
    yield buildFinding({
      scannerId: SCANNER_ID,
      magi: 'balthasar',
      pattern: 'yellow',
      title: 'BackgroundItems-v*.btm not found',
      evidence: 'No fallback source for login/background items.',
    });
    return;
  }

  const dump = await readBtmDump(btmPath);
  if (!dump) {
    yield buildFinding({
      scannerId: SCANNER_ID,
      magi: 'balthasar',
      pattern: 'yellow',
      title: 'BackgroundItems-v*.btm could not be parsed',
      evidence: `path: ${btmPath}\nplutil failed (BTM may need Full Disk Access).`,
      remediation: 'Grant Full Disk Access to your terminal, then re-run.',
    });
    return;
  }

  const identifiers = extractBtmIdentifiers(dump);
  yield buildFinding({
    scannerId: SCANNER_ID,
    magi: 'balthasar',
    pattern: identifiers.length > 12 ? 'yellow' : 'blue',
    title: `${identifiers.length} background/login item bundle id(s) (BTM)`,
    evidence: maybeRedact(identifiers.join('\n') || '(none)', context.redact),
    remediation:
      identifiers.length > 0
        ? `Review under System Settings → General → Login Items & Extensions. Source: ${btmPath}`
        : undefined,
  });
}

export const loginItemsScanner: Scanner = {
  id: SCANNER_ID,
  title: 'Login Items',
  magi: 'balthasar',
  run: scanLoginItems,
};
