import { hostname } from 'node:os';
import type { Finding, MagiCore, ScanContext, ScanProgress, Scanner } from './types.js';

export interface OrchestratorEvents {
  onProgress: (progress: ScanProgress) => void;
  onFinding: (finding: Finding) => void;
}

export async function executeScanners(
  scanners: Scanner[],
  events: OrchestratorEvents,
  options: { redact?: boolean } = {}
): Promise<void> {
  const context: ScanContext = {
    startedAt: Date.now(),
    hostname: hostname(),
    redact: options.redact ?? false,
  };

  const grouped = groupByMagi(scanners);

  await Promise.all(
    (Object.keys(grouped) as MagiCore[]).map((core) => runMagiCore(grouped[core] ?? [], context, events))
  );
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
  events: OrchestratorEvents
): Promise<void> {
  for (const scanner of scanners) {
    events.onProgress({ scannerId: scanner.id, magi: scanner.magi, status: 'running' });
    try {
      for await (const finding of scanner.run(context)) {
        events.onFinding(finding);
      }
      events.onProgress({ scannerId: scanner.id, magi: scanner.magi, status: 'completed' });
    } catch (error) {
      events.onProgress({
        scannerId: scanner.id,
        magi: scanner.magi,
        status: 'failed',
        message: error instanceof Error ? error.message : String(error),
      });
    }
  }
}
