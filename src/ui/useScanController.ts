import { useCallback, useEffect, useReducer, useRef } from 'react';
import { hostname } from 'node:os';
import { executeScanners, executeSingleScanner } from '../core/orchestrator.js';
import { loadAllScanners } from '../core/registry.js';
import { patternRank } from '../core/finding.js';
import { redactSensitive } from '../core/redact.js';
import { probePermissions, type Permissions } from '../core/permissions.js';
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
  cancelled: boolean;
  permissions: Permissions | null;
  rerunning: string | null;
}

type ScanAction =
  | { type: 'progress'; magi: MagiCore; scannerId: string; status: 'running' | 'completed' | 'failed' }
  | { type: 'finding'; finding: Finding }
  | { type: 'complete' }
  | { type: 'cancelled' }
  | { type: 'permissions'; permissions: Permissions }
  | { type: 'rerun-start'; scannerId: string }
  | { type: 'rerun-end' }
  | { type: 'drop-findings'; scannerId: string };

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
    cancelled: false,
    permissions: null,
    rerunning: null,
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
    case 'cancelled':
      return { ...state, scanComplete: true, cancelled: true };
    case 'permissions':
      return { ...state, permissions: action.permissions };
    case 'rerun-start':
      return { ...state, rerunning: action.scannerId };
    case 'rerun-end':
      return { ...state, rerunning: null };
    case 'drop-findings':
      return {
        ...state,
        findings: state.findings.filter((f) => f.scannerId !== action.scannerId),
        magi: {
          ...state.magi,
          ...Object.fromEntries(
            (Object.entries(state.magi) as Array<[MagiCore, MagiState]>).map(([core, value]) => {
              return [core, value];
            }),
          ),
        },
      };
  }
}

export function useScanController(options: { redact: boolean; bootComplete: boolean }) {
  const scannersRef = useRef<Scanner[]>(loadAllScanners());
  const [state, dispatch] = useReducer(
    reducer,
    { scanners: scannersRef.current, redact: options.redact },
    buildInitialState,
  );
  const abortRef = useRef<AbortController | null>(null);

  useEffect(() => {
    if (!options.bootComplete) return;
    const controller = new AbortController();
    abortRef.current = controller;
    let cancelled = false;
    void (async () => {
      const permissions = await probePermissions();
      if (!cancelled) dispatch({ type: 'permissions', permissions });

      await executeScanners(
        scannersRef.current,
        {
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
        },
        { redact: options.redact, signal: controller.signal },
      );
      if (cancelled) return;
      if (controller.signal.aborted) dispatch({ type: 'cancelled' });
      else dispatch({ type: 'complete' });
    })();
    return () => {
      cancelled = true;
      controller.abort();
    };
  }, [options.bootComplete, options.redact]);

  const cancel = useCallback(() => {
    abortRef.current?.abort();
  }, []);

  const rerun = useCallback(
    async (scannerId: string) => {
      const target = scannersRef.current.find((s) => s.id === scannerId);
      if (!target) return;
      dispatch({ type: 'drop-findings', scannerId });
      dispatch({ type: 'rerun-start', scannerId });
      await executeSingleScanner(
        target,
        {
          onProgress: () => undefined,
          onFinding: (finding) => dispatch({ type: 'finding', finding }),
        },
        { redact: options.redact },
      );
      dispatch({ type: 'rerun-end' });
    },
    [options.redact],
  );

  return { ...state, cancel, rerun };
}
