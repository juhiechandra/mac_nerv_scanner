import React from 'react';
import { Box, Text } from 'ink';
import { palette } from '../theme.js';

interface FooterBarProps {
  scanComplete: boolean;
}

const ACTIVE_HINTS = '↑/↓ navigate   enter: details   tab: switch pane   q: quit';
const COMPLETE_HINTS = '↑/↓ navigate   enter: details   r: write report   q: quit';

export function FooterBar({ scanComplete }: FooterBarProps) {
  const hint = scanComplete ? COMPLETE_HINTS : ACTIVE_HINTS;
  return (
    <Box borderStyle="single" borderColor={palette.ash} paddingX={1} justifyContent="space-between">
      <Text color={palette.ash}>{hint}</Text>
      <Text color={palette.nervOrange}>AT FIELD: {scanComplete ? 'DEPLOYED' : 'ACTIVE'}</Text>
    </Box>
  );
}
