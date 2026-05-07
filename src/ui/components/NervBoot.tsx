import React, { useEffect, useState } from 'react';
import { Box, Text } from 'ink';
import Gradient from 'ink-gradient';
import BigText from 'ink-big-text';
import { palette } from '../theme.js';

interface NervBootProps {
  onComplete: () => void;
  durationMs?: number;
}

const BOOT_LOG_LINES = [
  '> initialising MAGI sub-systems',
  '> mounting CASPER  ......... ONLINE',
  '> mounting MELCHIOR ........ ONLINE',
  '> mounting BALTHASAR ....... ONLINE',
  '> AT field synchronisation .. STABLE',
  '> entering audit mode',
];

function useTickedLines(totalLines: number, durationMs: number): number {
  const [visible, setVisible] = useState(0);
  useEffect(() => {
    const interval = durationMs / Math.max(1, totalLines);
    const handle = setInterval(() => {
      setVisible((current) => (current >= totalLines ? totalLines : current + 1));
    }, interval);
    return () => clearInterval(handle);
  }, [totalLines, durationMs]);
  return visible;
}

export function NervBoot({ onComplete, durationMs = 1400 }: NervBootProps) {
  const visible = useTickedLines(BOOT_LOG_LINES.length, durationMs);

  useEffect(() => {
    const timer = setTimeout(onComplete, durationMs + 350);
    return () => clearTimeout(timer);
  }, [onComplete, durationMs]);

  return (
    <Box flexDirection="column" paddingX={2} paddingY={1}>
      <Gradient name="pastel">
        <BigText text="NERV-SCAN" font="block" />
      </Gradient>
      <Text color={palette.ash}>// MAGI security audit suite — macOS</Text>
      <Box marginTop={1} flexDirection="column">
        {BOOT_LOG_LINES.slice(0, visible).map((line) => (
          <Text key={line} color={palette.terminalGreen}>
            {line}
          </Text>
        ))}
      </Box>
    </Box>
  );
}
