#!/usr/bin/env node
import React from 'react';
import { render } from 'ink';
import { Command } from 'commander';
import { App } from '../ui/App.js';
import { runHeadless } from './headless.js';

interface CliOptions {
  redact: boolean;
  noTui: boolean;
  report?: string;
}

function parseArgs(argv: string[]): CliOptions {
  const program = new Command();
  program
    .name('nerv-scan')
    .description('MAGI-driven macOS security audit suite')
    .option('--redact', 'redact hostname, username, MAC, IP from output')
    .option('--no-tui', 'run without the Ink TUI; print findings line-by-line')
    .option('-r, --report <path>', 'write report to this path (.md or .json)');
  program.parse(argv);
  const opts = program.opts();
  return {
    redact: opts.redact === true,
    noTui: opts.tui === false,
    report: typeof opts.report === 'string' ? opts.report : undefined,
  };
}

function canRenderInteractiveTui(): boolean {
  return process.stdin.isTTY === true && process.stdout.isTTY === true;
}

async function bootstrap(): Promise<void> {
  const options = parseArgs(process.argv);
  if (options.noTui || !canRenderInteractiveTui()) {
    await runHeadless({ redact: options.redact, reportPath: options.report });
    return;
  }
  const instance = render(<App redact={options.redact} reportPath={options.report} />);
  await instance.waitUntilExit();
}

bootstrap().catch((error) => {
  process.stderr.write(`fatal: ${error instanceof Error ? error.message : String(error)}\n`);
  process.exit(1);
});
