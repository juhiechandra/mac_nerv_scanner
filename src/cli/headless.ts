import { hostname } from 'node:os';
import { executeScanners } from '../core/orchestrator.js';
import { loadAllScanners } from '../core/registry.js';
import { writeReport } from '../reports/writeReport.js';
import { palette, patternColor, patternLabel } from '../ui/theme.js';
import { redactSensitive } from '../core/redact.js';
import type { Finding } from '../core/types.js';

const RESET = '\x1b[0m';

function colorize(hex: string, message: string): string {
  const normalized = hex.replace('#', '');
  const r = parseInt(normalized.substring(0, 2), 16);
  const g = parseInt(normalized.substring(2, 4), 16);
  const b = parseInt(normalized.substring(4, 6), 16);
  return `\x1b[38;2;${r};${g};${b}m${message}${RESET}`;
}

function emitFindingLine(finding: Finding): void {
  const tag = colorize(patternColor(finding.pattern), patternLabel(finding.pattern).padEnd(14));
  const scanner = colorize(palette.ash, finding.scannerId.padEnd(34));
  process.stdout.write(`${tag}  ${scanner}  ${finding.title}\n`);
}

interface HeadlessOptions {
  redact: boolean;
  reportPath?: string;
}

function reportHostname(redact: boolean): string {
  const raw = hostname();
  return redact ? redactSensitive(raw) : raw;
}

export async function runHeadless(options: HeadlessOptions): Promise<void> {
  const scanners = loadAllScanners();
  const collected: Finding[] = [];
  const startedAtMs = Date.now();
  process.stdout.write(colorize(palette.nervOrange, '\nNERV-SCAN // headless mode\n\n'));

  await executeScanners(scanners, {
    onProgress: () => undefined,
    onFinding: (finding) => {
      collected.push(finding);
      emitFindingLine(finding);
    },
  }, { redact: options.redact });

  const target = await writeReport(collected, {
    hostname: reportHostname(options.redact),
    startedAtMs,
    requestedPath: options.reportPath,
  });
  process.stdout.write(colorize(palette.terminalGreen, `\nMAGI consensus reached. Report: ${target}\n`));
}
