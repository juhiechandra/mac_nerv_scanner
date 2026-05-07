import React from 'react';
import { Text } from 'ink';

interface HexBarProps {
  total: number;
  filled: number;
  width?: number;
  color?: string;
}

const FILLED_BLOCK = '█';
const EMPTY_BLOCK = '░';

function fillRatio(filled: number, total: number): number {
  if (total === 0) return 0;
  return Math.min(1, Math.max(0, filled / total));
}

export function HexBar({ total, filled, width = 20, color = '#ffcaa6' }: HexBarProps) {
  const ratio = fillRatio(filled, total);
  const filledCells = Math.round(ratio * width);
  const emptyCells = width - filledCells;
  return (
    <Text color={color}>
      {FILLED_BLOCK.repeat(filledCells)}
      {EMPTY_BLOCK.repeat(emptyCells)}
    </Text>
  );
}
