import { runCommand } from '../../core/shell.js';
import { buildFinding } from '../../core/finding.js';
import { maybeRedact } from '../../core/redact.js';
import type { Finding, ScanContext, Scanner } from '../../core/types.js';

const SCANNER_ID = 'balthasar.login-items';

async function readLoginItems(): Promise<string> {
  const result = await runCommand('osascript', [
    '-e',
    'tell application "System Events" to get the name of every login item',
  ]);
  return (result.stdout + result.stderr).trim();
}

function parseLoginItems(output: string): string[] {
  if (!output || /execution error/i.test(output)) return [];
  return output
    .split(',')
    .map((entry) => entry.trim())
    .filter((entry) => entry.length > 0);
}

async function* scanLoginItems(context: ScanContext): AsyncIterable<Finding> {
  const raw = await readLoginItems();
  const items = parseLoginItems(raw);
  yield buildFinding({
    scannerId: SCANNER_ID,
    magi: 'balthasar',
    pattern: items.length > 8 ? 'yellow' : 'blue',
    title: `${items.length} login item(s)`,
    evidence: maybeRedact(items.length === 0 ? raw || '(none)' : items.join('\n'), context.redact),
    remediation:
      items.length > 0
        ? 'Audit System Settings → General → Login Items; persistence injected here runs at every login.'
        : undefined,
  });
}

export const loginItemsScanner: Scanner = {
  id: SCANNER_ID,
  title: 'Login Items',
  magi: 'balthasar',
  run: scanLoginItems,
};
