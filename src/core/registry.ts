import type { Scanner } from './types.js';
import { casperScanners } from '../scanners/casper/index.js';
import { melchiorScanners } from '../scanners/melchior/index.js';
import { balthasarScanners } from '../scanners/balthasar/index.js';

export function loadAllScanners(): Scanner[] {
  return [...casperScanners, ...melchiorScanners, ...balthasarScanners];
}

export function selectScanners(ids: string[]): Scanner[] {
  const all = loadAllScanners();
  if (ids.length === 0) return all;
  const selected = new Set(ids);
  return all.filter((scanner) => selected.has(scanner.id));
}
