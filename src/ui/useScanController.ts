import { useEffect, useReducer } from 'react';
import { hostname } from 'node:os';
import { executeScanners } from '../core/orchestrator.js';
import { loadAllScanners } from '../core/registry.js';
import { patternRank } from '../core/finding.js';
import { redactSensitive } from '../core/redact.js';
import type { Finding, MagiCore, Scanner } from '../core/types.js';

export interface MagiState {
  total: number;
  completed: number;
  active: string | null;
}

export interface ScanState {
  hostname: string;
  startedAtMs: number;
  findings: Finding[];
  magi: Record<MagiCore, MagiState>;
  scanComplete: boolean;
}

type ScanAction =
  | { type: 'progress'; magi: MagiCore; scannerId: string; status: 'running' | 'completed' | 'failed' }
  | { type: 'finding'; finding: Finding }
  | { type: 'complete' };

interface InitialStateInput {
  scanners: Scanner[];
  redact: boolean;
}

function buildInitialState({ scanners, redact }: InitialStateInput): ScanState {
  const magi: Record<MagiCore, MagiState> = {
    casper: { total: 0, completed: 0, active: null },
    melchior: { total: 0, completed: 0, active: null },
    balthasar: { total: 0, completed: 0, active: null },
  };
  for (const scanner of scanners) {
    magi[scanner.magi].total += 1;
  }
  const rawHost = hostname();
  return {
    hostname: redact ? redactSensitive(rawHost) : rawHost,
    startedAtMs: Date.now(),
    findings: [],
    magi,
    scanComplete: false,
  };
}

function reduceProgress(state: ScanState, action: Extract<ScanAction, { type: 'progress' }>): ScanState {
  const current = state.magi[action.magi];
  if (action.status === 'running') {
    return { ...state, magi: { ...state.magi, [action.magi]: { ...current, active: action.scannerId } } };
  }
  return {
    ...state,
    magi: {
      ...state.magi,
      [action.magi]: { ...current, completed: current.completed + 1, active: null },
    },
  };
}

function sortFindings(findings: Finding[]): Finding[] {
  return [...findings].sort((a, b) => patternRank(b.pattern) - patternRank(a.pattern));
}

function reducer(state: ScanState, action: ScanAction): ScanState {
  switch (action.type) {
    case 'progress':
      return reduceProgress(state, action);
    case 'finding':
      return { ...state, findings: sortFindings([...state.findings, action.finding]) };
    case 'complete':
      return { ...state, scanComplete: true };
  }
}

export function useScanController(options: { redact: boolean; bootComplete: boolean }) {
  const scanners = loadAllScanners();
  const [state, dispatch] = useReducer(reducer, { scanners, redact: options.redact }, buildInitialState);

  useEffect(() => {
    if (!options.bootComplete) return;
    let cancelled = false;
    void (async () => {
      await executeScanners(scanners, {
        onProgress: (progress) => {
          if (cancelled) return;
          if (progress.status === 'pending') return;
          dispatch({
            type: 'progress',
            magi: progress.magi,
            scannerId: progress.scannerId,
            status: progress.status,
          });
        },
        onFinding: (finding) => {
          if (cancelled) return;
          dispatch({ type: 'finding', finding });
        },
      }, { redact: options.redact });
      if (!cancelled) dispatch({ type: 'complete' });
    })();
    return () => {
      cancelled = true;
    };
  }, [options.bootComplete, options.redact]);

  return state;
}
