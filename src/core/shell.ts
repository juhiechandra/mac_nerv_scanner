import { spawn } from 'node:child_process';

export interface CommandResult {
  stdout: string;
  stderr: string;
  exitCode: number;
  timedOut: boolean;
}

export interface CommandOptions {
  timeoutMs?: number;
  input?: string;
}

const DEFAULT_TIMEOUT_MS = 8000;
const MAX_CONCURRENT_COMMANDS = 4;

let activeCommands = 0;
const waitQueue: Array<() => void> = [];

async function acquireSlot(): Promise<void> {
  if (activeCommands < MAX_CONCURRENT_COMMANDS) {
    activeCommands += 1;
    return;
  }
  await new Promise<void>((resolve) => {
    waitQueue.push(() => {
      activeCommands += 1;
      resolve();
    });
  });
}

function releaseSlot(): void {
  activeCommands -= 1;
  const next = waitQueue.shift();
  if (next) next();
}

export async function runCommand(
  binary: string,
  args: string[],
  options: CommandOptions = {}
): Promise<CommandResult> {
  await acquireSlot();
  const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;

  return new Promise((resolve) => {
    const child = spawn(binary, args, { shell: false });
    let stdout = '';
    let stderr = '';
    let timedOut = false;
    let settled = false;

    const finish = (result: CommandResult) => {
      if (settled) return;
      settled = true;
      releaseSlot();
      resolve(result);
    };

    const timer = setTimeout(() => {
      timedOut = true;
      child.kill('SIGKILL');
    }, timeoutMs);

    child.stdout.on('data', (chunk) => {
      stdout += chunk.toString();
    });
    child.stderr.on('data', (chunk) => {
      stderr += chunk.toString();
    });

    child.on('error', () => {
      clearTimeout(timer);
      finish({ stdout, stderr, exitCode: -1, timedOut });
    });

    child.on('close', (code) => {
      clearTimeout(timer);
      finish({ stdout, stderr, exitCode: code ?? -1, timedOut });
    });

    if (options.input) {
      child.stdin.write(options.input);
      child.stdin.end();
    }
  });
}

export async function runAndCaptureLines(
  binary: string,
  args: string[],
  options: CommandOptions = {}
): Promise<string[]> {
  const result = await runCommand(binary, args, options);
  return result.stdout
    .split('\n')
    .map((line) => line.trim())
    .filter((line) => line.length > 0);
}

export async function commandSucceeds(
  binary: string,
  args: string[],
  options: CommandOptions = {}
): Promise<boolean> {
  const result = await runCommand(binary, args, options);
  return result.exitCode === 0;
}

export function commandUnavailable(result: CommandResult): boolean {
  if (result.exitCode === 127 || result.exitCode === -1) return true;
  return /command not found|no such file/i.test(result.stderr);
}

export function commandFailed(result: CommandResult): boolean {
  return result.exitCode !== 0 || result.timedOut;
}

export function describeFailure(result: CommandResult): string {
  if (result.timedOut) return 'command timed out';
  if (commandUnavailable(result)) return 'command unavailable on this system';
  const trimmed = result.stderr.trim();
  return trimmed.length > 0 ? trimmed : `exit code ${result.exitCode}`;
}
