import React from 'react';
import { Box, Text } from 'ink';
import { palette, patternColor, patternLabel } from '../theme.js';
import type { Finding } from '../../core/types.js';

interface FindingDetailProps {
  finding: Finding | null;
}

function truncate(text: string, max: number): string {
  if (text.length <= max) return text;
  return `${text.slice(0, max)}\n…(${text.length - max} more chars)`;
}

export function FindingDetail({ finding }: FindingDetailProps) {
  if (!finding) {
    return (
      <Box borderStyle="single" borderColor={palette.ash} paddingX={1}>
        <Text color={palette.ash}>No finding selected.</Text>
      </Box>
    );
  }
  const color = patternColor(finding.pattern);
  return (
    <Box flexDirection="column" borderStyle="round" borderColor={color} paddingX={1}>
      <Text color={color} bold>
        {patternLabel(finding.pattern)} — {finding.title}
      </Text>
      <Text color={palette.ash}>scanner: {finding.scannerId}</Text>
      <Text color={palette.ash}>recorded: {finding.recordedAt}</Text>
      <Box marginTop={1} flexDirection="column">
        <Text color={palette.bone} bold>EVIDENCE</Text>
        <Text color={palette.bone}>{truncate(finding.evidence, 1200)}</Text>
      </Box>
      {finding.remediation ? (
        <Box marginTop={1} flexDirection="column">
          <Text color={palette.terminalGreen} bold>REMEDIATION</Text>
          <Text color={palette.bone}>{finding.remediation}</Text>
        </Box>
      ) : null}
      {finding.references && finding.references.length > 0 ? (
        <Box marginTop={1} flexDirection="column">
          <Text color={palette.blueCold} bold>REFERENCES</Text>
          {finding.references.map((reference) => (
            <Text key={reference} color={palette.blueCold}>
              {reference}
            </Text>
          ))}
        </Box>
      ) : null}
    </Box>
  );
}
