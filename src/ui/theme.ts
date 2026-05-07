import type { Pattern } from '../core/types.js';

export const palette = {
  nervOrange: '#ffcaa6',
  terminalGreen: '#b5ead7',
  alertRed: '#ffadad',
  warningYellow: '#fdffb6',
  blueCold: '#a0c4ff',
  bone: '#f4efe6',
  ash: '#a8a8a8',
  blackBlood: '#1a1a1a',
};

export function patternColor(pattern: Pattern): string {
  switch (pattern) {
    case 'red':
      return palette.alertRed;
    case 'orange':
      return palette.nervOrange;
    case 'yellow':
      return palette.warningYellow;
    case 'green':
      return palette.terminalGreen;
    case 'blue':
      return palette.blueCold;
  }
}

export function patternLabel(pattern: Pattern): string {
  return `PATTERN ${pattern.toUpperCase()}`;
}

export const magiCoreColors = {
  casper: palette.warningYellow,
  melchior: palette.terminalGreen,
  balthasar: palette.nervOrange,
};
