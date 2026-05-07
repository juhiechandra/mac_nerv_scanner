import React, { useMemo, useState } from 'react';
import { Box, Text, useApp, useInput } from 'ink';
import { NervBoot } from './components/NervBoot.js';
import { HeaderBar } from './components/HeaderBar.js';
import { FooterBar } from './components/FooterBar.js';
import { MagiPanel } from './components/MagiPanel.js';
import { FindingRow } from './components/FindingRow.js';
import { FindingDetail } from './components/FindingDetail.js';
import { useScanController } from './useScanController.js';
import { summarizePatterns } from './usePatternStats.js';
import { palette } from './theme.js';
import { writeReport } from '../reports/writeReport.js';

interface AppProps {
  redact: boolean;
  reportPath?: string;
}

const VISIBLE_ROWS = 10;

function clampSelection(index: number, length: number): number {
  if (length === 0) return 0;
  if (index < 0) return 0;
  if (index >= length) return length - 1;
  return index;
}

function visibleSlice<T>(items: T[], selectedIndex: number, windowSize: number): { slice: T[]; offset: number } {
  if (items.length <= windowSize) return { slice: items, offset: 0 };
  const halfWindow = Math.floor(windowSize / 2);
  const desiredStart = selectedIndex - halfWindow;
  const maxStart = items.length - windowSize;
  const offset = Math.min(Math.max(0, desiredStart), maxStart);
  return { slice: items.slice(offset, offset + windowSize), offset };
}

export function App({ redact, reportPath }: AppProps) {
  const { exit } = useApp();
  const [bootComplete, setBootComplete] = useState(false);
  const [selectedIndex, setSelectedIndex] = useState(0);
  const [showDetail, setShowDetail] = useState(false);
  const [reportStatus, setReportStatus] = useState<string | null>(null);

  const state = useScanController({ redact, bootComplete });
  const stats = useMemo(() => summarizePatterns(state.findings), [state.findings]);
  const safeIndex = clampSelection(selectedIndex, state.findings.length);
  const selected = state.findings[safeIndex] ?? null;

  useInput((input, key) => {
    if (input === 'q' || (key.ctrl && input === 'c')) {
      exit();
      return;
    }
    if (key.escape) {
      state.cancel();
      return;
    }
    if (state.findings.length === 0) return;
    if (key.upArrow) setSelectedIndex((current) => clampSelection(current - 1, state.findings.length));
    if (key.downArrow) setSelectedIndex((current) => clampSelection(current + 1, state.findings.length));
    if (key.return) setShowDetail((current) => !current);
    if (input === 's' && selected && state.rerunning === null) {
      void state.rerun(selected.scannerId);
    }
    if (input === 'r' && state.scanComplete) {
      void (async () => {
        const path = await writeReport(state.findings, {
          hostname: state.hostname,
          startedAtMs: state.startedAtMs,
          requestedPath: reportPath,
        });
        setReportStatus(`Report written: ${path}`);
      })();
    }
  });

  if (!bootComplete) {
    return <NervBoot onComplete={() => setBootComplete(true)} />;
  }

  const window = visibleSlice(state.findings, safeIndex, VISIBLE_ROWS);

  return (
    <Box flexDirection="column">
      <HeaderBar
        hostname={state.hostname}
        syncRatio={stats.syncRatio}
        totalFindings={stats.totalFindings}
        threatLevel={stats.threatLevel}
      />
      {state.permissions ? (
        <Box paddingX={1}>
          <Text color={palette.ash}>
            permissions:{' '}
            <Text color={state.permissions.fullDiskAccess ? palette.terminalGreen : palette.warningYellow}>
              FDA {state.permissions.fullDiskAccess ? 'granted' : 'denied'}
            </Text>{' '}
            ·{' '}
            <Text
              color={
                state.permissions.automation === true
                  ? palette.terminalGreen
                  : state.permissions.automation === false
                    ? palette.warningYellow
                    : palette.ash
              }
            >
              automation{' '}
              {state.permissions.automation === true
                ? 'granted'
                : state.permissions.automation === false
                  ? 'denied'
                  : 'unknown'}
            </Text>
          </Text>
        </Box>
      ) : null}
      <Box>
        <MagiPanel core="casper" title="Casper" total={state.magi.casper.total} completed={state.magi.casper.completed} active={state.magi.casper.active ?? undefined} />
        <MagiPanel core="melchior" title="Melchior" total={state.magi.melchior.total} completed={state.magi.melchior.completed} active={state.magi.melchior.active ?? undefined} />
        <MagiPanel core="balthasar" title="Balthasar" total={state.magi.balthasar.total} completed={state.magi.balthasar.completed} active={state.magi.balthasar.active ?? undefined} />
      </Box>
      <Box flexDirection="column" borderStyle="single" borderColor={palette.ash} paddingX={1} marginTop={1}>
        <Text color={palette.nervOrange} bold>FINDINGS</Text>
        {window.slice.length === 0 ? (
          <Text color={palette.ash}>(awaiting MAGI consensus…)</Text>
        ) : (
          window.slice.map((finding, index) => (
            <FindingRow
              key={finding.id}
              finding={finding}
              selected={index + window.offset === safeIndex}
            />
          ))
        )}
      </Box>
      {showDetail ? <FindingDetail finding={selected} /> : null}
      {state.rerunning ? (
        <Box paddingX={1}>
          <Text color={palette.warningYellow}>rerunning {state.rerunning}…</Text>
        </Box>
      ) : null}
      {state.cancelled ? (
        <Box paddingX={1}>
          <Text color={palette.warningYellow}>scan cancelled</Text>
        </Box>
      ) : null}
      {reportStatus ? (
        <Box paddingX={1}>
          <Text color={palette.terminalGreen}>{reportStatus}</Text>
        </Box>
      ) : null}
      <FooterBar scanComplete={state.scanComplete} />
    </Box>
  );
}
