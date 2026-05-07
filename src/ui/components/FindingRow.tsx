import React from 'react';
import { Box, Text } from 'ink';
import { palette, patternColor, patternLabel } from '../theme.js';
import type { Finding } from '../../core/types.js';

interface FindingRowProps {
  finding: Finding;
  selected: boolean;
}

function indicator(selected: boolean): string {
  return selected ? '▶' : ' ';
}

export function FindingRow({ finding, selected }: FindingRowProps) {
  const color = patternColor(finding.pattern);
  return (
    <Box>
      <Text color={selected ? palette.nervOrange : palette.ash}>{indicator(selected)} </Text>
      <Box width={18}>
        <Text color={color}>{patternLabel(finding.pattern)}</Text>
      </Box>
      <Box width={20}>
        <Text color={palette.ash}>{finding.scannerId}</Text>
      </Box>
      <Text color={selected ? palette.bone : palette.ash}>{finding.title}</Text>
    </Box>
  );
}
