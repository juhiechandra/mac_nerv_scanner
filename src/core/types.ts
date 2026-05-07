export type MagiCore = 'casper' | 'melchior' | 'balthasar';

export type Pattern = 'blue' | 'green' | 'yellow' | 'orange' | 'red';

export interface ScannerRequirements {
  fullDiskAccess?: boolean;
  root?: boolean;
  network?: boolean;
}

export interface Finding {
  id: string;
  scannerId: string;
  magi: MagiCore;
  pattern: Pattern;
  title: string;
  evidence: string;
  remediation?: string;
  references?: string[];
  recordedAt: string;
}

export interface ScanContext {
  startedAt: number;
  hostname: string;
  redact: boolean;
}

export interface Scanner {
  id: string;
  title: string;
  magi: MagiCore;
  requires?: ScannerRequirements;
  run(context: ScanContext): AsyncIterable<Finding>;
}

export interface ScanProgress {
  scannerId: string;
  magi: MagiCore;
  status: 'pending' | 'running' | 'completed' | 'failed';
  message?: string;
}

export interface ScanReport {
  generatedAt: string;
  hostname: string;
  durationMs: number;
  findings: Finding[];
  summary: Record<Pattern, number>;
}
