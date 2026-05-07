import { runAndCaptureLines } from '../../core/shell.js';
import { buildFinding, classifyByThreshold } from '../../core/finding.js';
import { maybeRedact } from '../../core/redact.js';
import type { Finding, ScanContext, Scanner } from '../../core/types.js';

const SCANNER_ID = 'melchior.listening-sockets';

async function listListeningSockets(): Promise<string[]> {
  return runAndCaptureLines('lsof', ['-nP', '-iTCP', '-sTCP:LISTEN']);
}

function dropHeaderLine(lines: string[]): string[] {
  if (lines.length === 0) return lines;
  const [first, ...rest] = lines;
  return /COMMAND/i.test(first ?? '') ? rest : lines;
}

async function* scanListeningSockets(context: ScanContext): AsyncIterable<Finding> {
  const lines = dropHeaderLine(await listListeningSockets());
  const pattern = classifyByThreshold(lines.length, { yellow: 5, orange: 15, red: 40 });
  yield buildFinding({
    scannerId: SCANNER_ID,
    magi: 'melchior',
    pattern,
    title: `${lines.length} TCP socket(s) in LISTEN state`,
    evidence: lines.length === 0 ? 'No listening TCP sockets.' : maybeRedact(lines.join('\n'), context.redact),
    remediation:
      lines.length > 0 ? 'Cross-reference each owner process with expected services; investigate the unfamiliar.' : undefined,
  });
}

export const listeningSocketsScanner: Scanner = {
  id: SCANNER_ID,
  title: 'Listening Sockets',
  magi: 'melchior',
  run: scanListeningSockets,
};
