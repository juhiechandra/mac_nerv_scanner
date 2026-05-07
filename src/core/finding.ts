import { randomUUID } from 'node:crypto';
import type { Finding, MagiCore, Pattern } from './types.js';

export interface FindingDraft {
  scannerId: string;
  magi: MagiCore;
  pattern: Pattern;
  title: string;
  evidence: string;
  remediation?: string;
  references?: string[];
}

export function buildFinding(draft: FindingDraft): Finding {
  return {
    id: randomUUID(),
    scannerId: draft.scannerId,
    magi: draft.magi,
    pattern: draft.pattern,
    title: draft.title,
    evidence: draft.evidence,
    remediation: draft.remediation,
    references: draft.references,
    recordedAt: new Date().toISOString(),
  };
}

export function patternRank(pattern: Pattern): number {
  switch (pattern) {
    case 'red':
      return 5;
    case 'orange':
      return 4;
    case 'yellow':
      return 3;
    case 'green':
      return 2;
    case 'blue':
      return 1;
  }
}

export function classifyByThreshold(
  observed: number,
  thresholds: { yellow?: number; orange?: number; red?: number }
): Pattern {
  if (thresholds.red !== undefined && observed >= thresholds.red) return 'red';
  if (thresholds.orange !== undefined && observed >= thresholds.orange) return 'orange';
  if (thresholds.yellow !== undefined && observed >= thresholds.yellow) return 'yellow';
  return 'blue';
}
