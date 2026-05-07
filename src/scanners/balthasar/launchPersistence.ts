import { readdir } from 'node:fs/promises';
import { homedir } from 'node:os';
import { join } from 'node:path';
import { buildFinding, classifyByThreshold } from '../../core/finding.js';
import { maybeRedact } from '../../core/redact.js';
import type { Finding, Pattern, ScanContext, Scanner } from '../../core/types.js';

const SCANNER_ID = 'balthasar.launch-persistence';

interface PersistenceLocation {
  label: string;
  path: string;
  systemOwned: boolean;
}

function persistenceLocations(): PersistenceLocation[] {
  return [
    { label: 'System LaunchAgents', path: '/Library/LaunchAgents', systemOwned: true },
    { label: 'System LaunchDaemons', path: '/Library/LaunchDaemons', systemOwned: true },
    { label: 'User LaunchAgents', path: join(homedir(), 'Library', 'LaunchAgents'), systemOwned: false },
  ];
}

async function listPlistEntries(directory: string): Promise<string[]> {
  try {
    const entries = await readdir(directory);
    return entries.filter((entry) => entry.endsWith('.plist'));
  } catch {
    return [];
  }
}

function patternForLocation(location: PersistenceLocation, count: number): Pattern {
  if (location.systemOwned) {
    return classifyByThreshold(count, { yellow: 1, orange: 25 });
  }
  return classifyByThreshold(count, { yellow: 5, orange: 15 });
}

async function* scanLaunchPersistence(context: ScanContext): AsyncIterable<Finding> {
  for (const location of persistenceLocations()) {
    const entries = await listPlistEntries(location.path);
    yield buildFinding({
      scannerId: SCANNER_ID,
      magi: 'balthasar',
      pattern: patternForLocation(location, entries.length),
      title: `${location.label}: ${entries.length} plist(s)`,
      evidence: maybeRedact(entries.length === 0 ? '(empty)' : entries.join('\n'), context.redact),
      remediation:
        entries.length > 0
          ? `Review each plist under ${location.path}; persistence here survives reboots.`
          : undefined,
    });
  }
}

export const launchPersistenceScanner: Scanner = {
  id: SCANNER_ID,
  title: 'Launch Persistence',
  magi: 'balthasar',
  run: scanLaunchPersistence,
};
