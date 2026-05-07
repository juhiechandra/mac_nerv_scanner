import React from 'react';
import { Box, Text } from 'ink';
import { HexBar } from './HexBar.js';
import { magiCoreColors, palette } from '../theme.js';
import type { MagiCore } from '../../core/types.js';

interface MagiPanelProps {
  core: MagiCore;
  title: string;
  total: number;
  completed: number;
  active?: string;
}

function panelStateLabel(total: number, completed: number, active?: string): string {
  if (total === 0) return 'STAND BY';
  if (completed >= total) return 'COMPLETE';
  if (active) return 'SCANNING';
  return 'PENDING';
}

export function MagiPanel({ core, title, total, completed, active }: MagiPanelProps) {
  const color = magiCoreColors[core];
  const status = panelStateLabel(total, completed, active);
  return (
    <Box flexDirection="column" borderStyle="double" borderColor={color} paddingX={1} width={28}>
      <Text color={color} bold>
        {title.toUpperCase()}
      </Text>
      <Box marginTop={1}>
        <HexBar total={total} filled={completed} width={20} color={color} />
      </Box>
      <Text color={palette.bone}>
        {completed}/{total} {status}
      </Text>
      <Text color={palette.ash}>{active ? `▶ ${active}` : ' '}</Text>
    </Box>
  );
}
