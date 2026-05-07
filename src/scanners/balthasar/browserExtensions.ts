import { readdir, readFile } from 'node:fs/promises';
import { homedir } from 'node:os';
import { join } from 'node:path';
import { buildFinding } from '../../core/finding.js';
import { maybeRedact } from '../../core/redact.js';
import type { Finding, Pattern, ScanContext, Scanner } from '../../core/types.js';

const SCANNER_ID = 'balthasar.browser-extensions';

const SENSITIVE_PERMISSIONS = new Set([
  '<all_urls>',
  '*://*/*',
  'http://*/*',
  'https://*/*',
  'tabs',
  'cookies',
  'webRequest',
  'webRequestBlocking',
  'declarativeNetRequest',
  'debugger',
  'proxy',
  'desktopCapture',
  'history',
  'nativeMessaging',
]);

interface ChromiumTarget {
  name: string;
  extensionsRoot: string;
}

interface ExtensionDescription {
  browser: string;
  id: string;
  name: string;
  version: string | null;
  riskyPermissions: string[];
}

function chromiumTargets(): ChromiumTarget[] {
  const home = homedir();
  return [
    { name: 'Chrome', extensionsRoot: join(home, 'Library', 'Application Support', 'Google', 'Chrome', 'Default', 'Extensions') },
    { name: 'Brave', extensionsRoot: join(home, 'Library', 'Application Support', 'BraveSoftware', 'Brave-Browser', 'Default', 'Extensions') },
    { name: 'Edge', extensionsRoot: join(home, 'Library', 'Application Support', 'Microsoft Edge', 'Default', 'Extensions') },
    { name: 'Arc', extensionsRoot: join(home, 'Library', 'Application Support', 'Arc', 'User Data', 'Default', 'Extensions') },
  ];
}

async function safeReaddir(path: string): Promise<string[]> {
  try {
    return await readdir(path);
  } catch {
    return [];
  }
}

async function readManifest(path: string): Promise<Record<string, unknown> | null> {
  try {
    const text = await readFile(path, 'utf8');
    return JSON.parse(text);
  } catch {
    return null;
  }
}

function pickRiskyPermissions(manifest: Record<string, unknown>): string[] {
  const declared: string[] = [];
  if (Array.isArray(manifest.permissions)) declared.push(...(manifest.permissions as unknown[]).map(String));
  if (Array.isArray(manifest.host_permissions)) declared.push(...(manifest.host_permissions as unknown[]).map(String));
  if (Array.isArray(manifest.optional_permissions)) declared.push(...(manifest.optional_permissions as unknown[]).map(String));
  return declared.filter((p) => SENSITIVE_PERMISSIONS.has(p) || p.endsWith('://*/*'));
}

async function inspectChromiumExtensions(target: ChromiumTarget): Promise<ExtensionDescription[]> {
  const ids = (await safeReaddir(target.extensionsRoot)).filter((entry) => !entry.startsWith('.') && entry !== 'Temp');
  const descriptions: ExtensionDescription[] = [];
  for (const id of ids) {
    const versions = (await safeReaddir(join(target.extensionsRoot, id))).filter((v) => !v.startsWith('.'));
    if (versions.length === 0) continue;
    versions.sort();
    const latest = versions[versions.length - 1] ?? '';
    const manifestPath = join(target.extensionsRoot, id, latest, 'manifest.json');
    const manifest = await readManifest(manifestPath);
    descriptions.push({
      browser: target.name,
      id,
      name: typeof manifest?.name === 'string' ? (manifest.name as string) : id,
      version: typeof manifest?.version === 'string' ? (manifest.version as string) : latest,
      riskyPermissions: manifest ? pickRiskyPermissions(manifest) : [],
    });
  }
  return descriptions;
}

async function inspectFirefoxExtensions(): Promise<ExtensionDescription[]> {
  const root = join(homedir(), 'Library', 'Application Support', 'Firefox', 'Profiles');
  const profiles = await safeReaddir(root);
  const descriptions: ExtensionDescription[] = [];
  for (const profile of profiles) {
    const manifest = await readManifest(join(root, profile, 'extensions.json'));
    const addons = (manifest?.addons as unknown[]) ?? [];
    if (!Array.isArray(addons)) continue;
    for (const entry of addons as Record<string, unknown>[]) {
      if (entry.type !== 'extension') continue;
      const defaults = (entry.defaultLocale as Record<string, unknown> | undefined) ?? {};
      descriptions.push({
        browser: 'Firefox',
        id: String(entry.id ?? '(unknown)'),
        name: String(defaults.name ?? entry.id ?? '(unnamed)'),
        version: typeof entry.version === 'string' ? (entry.version as string) : null,
        riskyPermissions: Array.isArray(entry.userPermissions)
          ? (entry.userPermissions as unknown[]).map(String).filter((p) => SENSITIVE_PERMISSIONS.has(p) || p.endsWith('://*/*'))
          : [],
      });
    }
  }
  return descriptions;
}

function patternForExtension(ext: ExtensionDescription): Pattern {
  if (ext.riskyPermissions.length === 0) return 'blue';
  if (ext.riskyPermissions.length >= 4) return 'orange';
  return 'yellow';
}

async function* scanBrowserExtensions(context: ScanContext): AsyncIterable<Finding> {
  const chromium = await Promise.all(chromiumTargets().map(inspectChromiumExtensions));
  const all = [...chromium.flat(), ...(await inspectFirefoxExtensions())];

  if (all.length === 0) {
    yield buildFinding({
      scannerId: SCANNER_ID,
      magi: 'balthasar',
      pattern: 'blue',
      title: 'No browser extensions detected',
      evidence: 'No Chromium-family or Firefox extensions found in user library.',
    });
    return;
  }

  const grouped = new Map<string, ExtensionDescription[]>();
  for (const ext of all) {
    const key = ext.browser;
    if (!grouped.has(key)) grouped.set(key, []);
    grouped.get(key)?.push(ext);
  }

  for (const [browser, extensions] of grouped) {
    yield buildFinding({
      scannerId: SCANNER_ID,
      magi: 'balthasar',
      pattern: extensions.length >= 20 ? 'yellow' : 'blue',
      title: `${browser}: ${extensions.length} extension(s) installed`,
      evidence: maybeRedact(
        extensions.map((e) => `${e.name} (${e.id}) v${e.version ?? '?'}`).join('\n'),
        context.redact,
      ),
    });

    for (const ext of extensions) {
      const pattern = patternForExtension(ext);
      if (pattern === 'blue') continue;
      yield buildFinding({
        scannerId: SCANNER_ID,
        magi: 'balthasar',
        pattern,
        title: `${browser} extension with ${ext.riskyPermissions.length} sensitive permission(s): ${ext.name}`,
        evidence: maybeRedact(
          [`id: ${ext.id}`, `version: ${ext.version ?? '?'}`, `permissions: ${ext.riskyPermissions.join(', ')}`].join('\n'),
          context.redact,
        ),
        remediation:
          'Permissions like <all_urls> / webRequest / cookies let an extension read every page you visit. Verify the publisher.',
      });
    }
  }
}

export const browserExtensionsScanner: Scanner = {
  id: SCANNER_ID,
  title: 'Browser Extensions',
  magi: 'balthasar',
  run: scanBrowserExtensions,
};
