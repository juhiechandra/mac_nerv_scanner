import type { Finding, Pattern } from '../core/types.js';
import { patternRank } from '../core/finding.js';

export interface PatternStats {
  countsByPattern: Record<Pattern, number>;
  totalFindings: number;
  syncRatio: number;
  threatLevel: number;
}

const PATTERN_KEYS: Pattern[] = ['blue', 'green', 'yellow', 'orange', 'red'];

function emptyCounts(): Record<Pattern, number> {
  return PATTERN_KEYS.reduce(
    (acc, key) => {
      acc[key] = 0;
      return acc;
    },
    {} as Record<Pattern, number>
  );
}

function computeSyncRatio(findings: Finding[]): number {
  if (findings.length === 0) return 1;
  const benignWeight = findings.filter((finding) => patternRank(finding.pattern) <= 2).length;
  return benignWeight / findings.length;
}

function computeThreatLevel(counts: Record<Pattern, number>): number {
  return counts.red * 5 + counts.orange * 3 + counts.yellow;
}

export function summarizePatterns(findings: Finding[]): PatternStats {
  const countsByPattern = emptyCounts();
  for (const finding of findings) {
    countsByPattern[finding.pattern] += 1;
  }
  return {
    countsByPattern,
    totalFindings: findings.length,
    syncRatio: computeSyncRatio(findings),
    threatLevel: computeThreatLevel(countsByPattern),
  };
}
