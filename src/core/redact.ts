import { homedir, hostname, userInfo } from 'node:os';

const REDACTED = '[REDACTED]';

export function redactSensitive(input: string): string {
  const home = homedir();
  const user = userInfo().username;
  const host = hostname();

  return input
    .replaceAll(home, '~')
    .replaceAll(user, REDACTED)
    .replaceAll(host, REDACTED)
    .replaceAll(/([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}/g, REDACTED)
    .replaceAll(/\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/g, REDACTED);
}

export function maybeRedact(input: string, redact: boolean): string {
  return redact ? redactSensitive(input) : input;
}
