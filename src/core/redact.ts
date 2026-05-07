import { homedir, hostname, userInfo } from 'node:os';

const REDACTED = '[REDACTED]';

const MAC_PATTERN = /([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}/g;
const IPV4_PATTERN = /\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/g;
const IPV6_PATTERN = /\b(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}\b/g;
const UUID_PATTERN = /\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b/g;
const EMAIL_PATTERN = /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g;
const SERIAL_LINE_PATTERN = /(Serial Number(?:\s*\(system\))?:\s*)([A-Z0-9]{8,})/gi;
const HARDWARE_UUID_LINE_PATTERN = /(Hardware UUID:\s*)([0-9A-Fa-f-]+)/g;
const PROVISIONING_UUID_PATTERN = /(Provisioning UDID:\s*)([0-9A-Fa-f-]+)/g;

const dynamicRedactions = new Set<string>();

export function registerSensitiveValue(value: string): void {
  const trimmed = value.trim();
  if (trimmed.length > 2) dynamicRedactions.add(trimmed);
}

export function clearDynamicRedactions(): void {
  dynamicRedactions.clear();
}

function applyDynamicRedactions(input: string): string {
  let output = input;
  for (const value of dynamicRedactions) {
    output = output.split(value).join(REDACTED);
  }
  return output;
}

export function redactSensitive(input: string): string {
  const home = homedir();
  const user = userInfo().username;
  const host = hostname();

  let output = input;
  if (home.length > 0) output = output.split(home).join('~');
  if (user.length > 0) output = output.split(user).join(REDACTED);
  if (host.length > 0) output = output.split(host).join(REDACTED);

  output = output
    .replace(MAC_PATTERN, REDACTED)
    .replace(IPV4_PATTERN, REDACTED)
    .replace(IPV6_PATTERN, REDACTED)
    .replace(UUID_PATTERN, REDACTED)
    .replace(EMAIL_PATTERN, REDACTED)
    .replace(SERIAL_LINE_PATTERN, `$1${REDACTED}`)
    .replace(HARDWARE_UUID_LINE_PATTERN, `$1${REDACTED}`)
    .replace(PROVISIONING_UUID_PATTERN, `$1${REDACTED}`);

  return applyDynamicRedactions(output);
}

export function maybeRedact(input: string, redact: boolean): string {
  return redact ? redactSensitive(input) : input;
}
