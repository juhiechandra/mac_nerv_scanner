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

export async function runCommand(
  binary: string,
  args: string[],
  options: CommandOptions = {}
): Promise<CommandResult> {
  const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;

  return new Promise((resolve) => {
    const child = spawn(binary, args, { shell: false });
    let stdout = '';
    let stderr = '';
    let timedOut = false;

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
      resolve({ stdout, stderr, exitCode: -1, timedOut });
    });

    child.on('close', (code) => {
      clearTimeout(timer);
      resolve({ stdout, stderr, exitCode: code ?? -1, timedOut });
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
