import { hostname } from 'node:os';
import type { Finding, MagiCore, ScanContext, ScanProgress, Scanner } from './types.js';

export interface OrchestratorEvents {
  onProgress: (progress: ScanProgress) => void;
  onFinding: (finding: Finding) => void;
}

export interface OrchestratorOptions {
  redact?: boolean;
  signal?: AbortSignal;
}

export async function executeScanners(
  scanners: Scanner[],
  events: OrchestratorEvents,
  options: OrchestratorOptions = {},
): Promise<void> {
  const context: ScanContext = {
    startedAt: Date.now(),
    hostname: hostname(),
    redact: options.redact ?? false,
  };

  const grouped = groupByMagi(scanners);

  await Promise.all(
    (Object.keys(grouped) as MagiCore[]).map((core) =>
      runMagiCore(grouped[core] ?? [], context, events, options.signal),
    ),
  );
}

export async function executeSingleScanner(
  scanner: Scanner,
  events: OrchestratorEvents,
  options: OrchestratorOptions = {},
): Promise<void> {
  const context: ScanContext = {
    startedAt: Date.now(),
    hostname: hostname(),
    redact: options.redact ?? false,
  };
  await runScanner(scanner, context, events, options.signal);
}

function groupByMagi(scanners: Scanner[]): Record<MagiCore, Scanner[]> {
  const groups: Record<MagiCore, Scanner[]> = { casper: [], melchior: [], balthasar: [] };
  for (const scanner of scanners) {
    groups[scanner.magi].push(scanner);
  }
  return groups;
}

async function runMagiCore(
  scanners: Scanner[],
  context: ScanContext,
  events: OrchestratorEvents,
  signal?: AbortSignal,
): Promise<void> {
  for (const scanner of scanners) {
    if (signal?.aborted) {
      events.onProgress({
        scannerId: scanner.id,
        magi: scanner.magi,
        status: 'failed',
        message: 'cancelled',
      });
      continue;
    }
    await runScanner(scanner, context, events, signal);
  }
}

async function runScanner(
  scanner: Scanner,
  context: ScanContext,
  events: OrchestratorEvents,
  signal?: AbortSignal,
): Promise<void> {
  events.onProgress({ scannerId: scanner.id, magi: scanner.magi, status: 'running' });
  try {
    for await (const finding of scanner.run(context)) {
      if (signal?.aborted) break;
      events.onFinding(finding);
    }
    events.onProgress({
      scannerId: scanner.id,
      magi: scanner.magi,
      status: signal?.aborted ? 'failed' : 'completed',
      message: signal?.aborted ? 'cancelled' : undefined,
    });
  } catch (error) {
    events.onProgress({
      scannerId: scanner.id,
      magi: scanner.magi,
      status: 'failed',
      message: error instanceof Error ? error.message : String(error),
    });
  }
}
