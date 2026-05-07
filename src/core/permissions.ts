import { open } from 'node:fs/promises';
import { runCommand } from './shell.js';

export interface Permissions {
  fullDiskAccess: boolean;
  automation: boolean | null;
}

const FDA_PROBE_PATH = '/Library/Application Support/com.apple.TCC/TCC.db';

async function probeFullDiskAccess(): Promise<boolean> {
  try {
    const handle = await open(FDA_PROBE_PATH, 'r');
    await handle.close();
    return true;
  } catch {
    return false;
  }
}

async function probeAutomation(): Promise<boolean | null> {
  const result = await runCommand(
    'osascript',
    ['-e', 'tell application "System Events" to count processes'],
    { timeoutMs: 4000 },
  );
  if (result.exitCode === 0) return true;
  if (/\(-1743\)|not authorized|not allowed assistive access/i.test(result.stderr)) return false;
  return null;
}

export async function probePermissions(): Promise<Permissions> {
  const [fullDiskAccess, automation] = await Promise.all([
    probeFullDiskAccess(),
    probeAutomation(),
  ]);
  return { fullDiskAccess, automation };
}
