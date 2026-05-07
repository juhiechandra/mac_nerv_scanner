import { readdir } from 'node:fs/promises';
import { homedir } from 'node:os';
import { join } from 'node:path';
import { runCommand } from '../../core/shell.js';
import { buildFinding, classifyByThreshold } from '../../core/finding.js';
import { maybeRedact } from '../../core/redact.js';
import type { Finding, Pattern, ScanContext, Scanner } from '../../core/types.js';

const SCANNER_ID = 'balthasar.launch-persistence';
const PER_LOCATION_INSPECTION_CAP = 25;

interface PersistenceLocation {
  label: string;
  path: string;
  systemOwned: boolean;
}

interface PlistInspection {
  file: string;
  executable: string | null;
  runAtLoad: boolean | null;
  signed: 'apple' | 'thirdparty' | 'adhoc' | 'unsigned' | 'unknown';
  signature: string;
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

async function inspectPlist(filePath: string): Promise<PlistInspection> {
  const inspection: PlistInspection = {
    file: filePath,
    executable: null,
    runAtLoad: null,
    signed: 'unknown',
    signature: '',
  };

  const plist = await runCommand('plutil', ['-convert', 'json', '-o', '-', filePath]);
  if (plist.exitCode !== 0) return inspection;

  try {
    const parsed = JSON.parse(plist.stdout);
    const args = parsed?.ProgramArguments;
    const executable = (Array.isArray(args) && args.length > 0 ? args[0] : parsed?.Program) as
      | string
      | undefined;
    inspection.executable = typeof executable === 'string' ? executable : null;
    inspection.runAtLoad = typeof parsed?.RunAtLoad === 'boolean' ? parsed.RunAtLoad : null;
  } catch {
    return inspection;
  }

  if (!inspection.executable) return inspection;

  const codesign = await runCommand('codesign', ['-dv', '--verbose=2', inspection.executable]);
  inspection.signature = codesign.stderr.trim();
  if (codesign.exitCode !== 0) {
    inspection.signed = /code object is not signed/i.test(codesign.stderr) ? 'unsigned' : 'unknown';
    return inspection;
  }
  if (/Authority=(Apple Root CA|Software Signing|Apple Mac OS Application Signing|Apple iPhone OS Application Signing)/i.test(codesign.stderr)) {
    inspection.signed = 'apple';
  } else if (/Signature=adhoc/i.test(codesign.stderr) || /\badhoc\b/i.test(codesign.stderr)) {
    inspection.signed = 'adhoc';
  } else if (/TeamIdentifier=(?!not set)/i.test(codesign.stderr) || /Authority=Developer ID/i.test(codesign.stderr)) {
    inspection.signed = 'thirdparty';
  } else if (/Authority=/i.test(codesign.stderr)) {
    inspection.signed = 'thirdparty';
  } else {
    inspection.signed = 'unknown';
  }
  return inspection;
}

function patternForLocation(location: PersistenceLocation, count: number): Pattern {
  if (location.systemOwned) {
    return classifyByThreshold(count, { yellow: 1, orange: 25 });
  }
  return classifyByThreshold(count, { yellow: 5, orange: 15 });
}

function patternForInspection(inspection: PlistInspection): Pattern {
  if (inspection.signed === 'unsigned') return 'orange';
  if (inspection.signed === 'adhoc') return 'yellow';
  if (inspection.signed === 'thirdparty') return 'blue';
  if (inspection.signed === 'unknown') return 'blue';
  return 'blue';
}

function summarizeInspection(inspection: PlistInspection): string {
  return [
    `executable: ${inspection.executable ?? '(none)'}`,
    `runAtLoad: ${inspection.runAtLoad ?? '(unspecified)'}`,
    `signature: ${inspection.signed}`,
    inspection.signature ? inspection.signature.split('\n').slice(0, 4).join('\n') : '',
  ]
    .filter((line) => line.length > 0)
    .join('\n');
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

    const toInspect = entries.slice(0, PER_LOCATION_INSPECTION_CAP);
    for (const entry of toInspect) {
      const fullPath = join(location.path, entry);
      const inspection = await inspectPlist(fullPath);
      const pattern = patternForInspection(inspection);
      if (pattern === 'blue') continue;
      yield buildFinding({
        scannerId: SCANNER_ID,
        magi: 'balthasar',
        pattern,
        title: `${entry} → ${inspection.signed}`,
        evidence: maybeRedact(`${fullPath}\n${summarizeInspection(inspection)}`, context.redact),
        remediation:
          inspection.signed === 'unsigned' || inspection.signed === 'adhoc'
            ? 'Verify provenance — unsigned/adhoc binaries auto-running at login are a classic persistence vector.'
            : undefined,
      });
    }

    if (entries.length > PER_LOCATION_INSPECTION_CAP) {
      yield buildFinding({
        scannerId: SCANNER_ID,
        magi: 'balthasar',
        pattern: 'yellow',
        title: `${entries.length - PER_LOCATION_INSPECTION_CAP} additional plist(s) in ${location.label} not inspected`,
        evidence: `Inspection capped at ${PER_LOCATION_INSPECTION_CAP} per location for performance.`,
        remediation: `Spot-check the remainder under ${location.path}.`,
      });
    }
  }
}

export const launchPersistenceScanner: Scanner = {
  id: SCANNER_ID,
  title: 'Launch Persistence',
  magi: 'balthasar',
  run: scanLaunchPersistence,
};
