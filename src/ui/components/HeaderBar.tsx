import React from 'react';
import { Box, Text } from 'ink';
import { palette } from '../theme.js';

interface HeaderBarProps {
  hostname: string;
  syncRatio: number;
  totalFindings: number;
  threatLevel: number;
}

function formatSync(ratio: number): string {
  return `${(ratio * 100).toFixed(1)}%`;
}

function formatDate(): string {
  const now = new Date();
  return now.toISOString().slice(0, 19).replace('T', ' ');
}

export function HeaderBar({ hostname, syncRatio, totalFindings, threatLevel }: HeaderBarProps) {
  return (
    <Box borderStyle="double" borderColor={palette.nervOrange} paddingX={1} justifyContent="space-between">
      <Text color={palette.nervOrange} bold>
        NERV TERMINAL
      </Text>
      <Text color={palette.bone}>
        host:<Text color={palette.terminalGreen}> {hostname}</Text>
      </Text>
      <Text color={palette.bone}>
        sync ratio:<Text color={palette.terminalGreen}> {formatSync(syncRatio)}</Text>
      </Text>
      <Text color={palette.bone}>
        findings:<Text color={palette.warningYellow}> {totalFindings}</Text>
      </Text>
      <Text color={palette.bone}>
        threat lv:<Text color={palette.alertRed}> {threatLevel}</Text>
      </Text>
      <Text color={palette.ash}>{formatDate()}</Text>
    </Box>
  );
}
