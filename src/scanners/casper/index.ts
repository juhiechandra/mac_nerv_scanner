import type { Scanner } from '../../core/types.js';
import { hardwareProfileScanner } from './hardwareProfile.js';
import { sipScanner } from './systemIntegrityProtection.js';
import { fileVaultScanner } from './fileVault.js';
import { gatekeeperScanner } from './gatekeeper.js';
import { softwareUpdatesScanner } from './softwareUpdates.js';
import { kernelExtensionsScanner } from './kernelExtensions.js';
import { configurationProfilesScanner } from './configurationProfiles.js';

export const casperScanners: Scanner[] = [
  hardwareProfileScanner,
  sipScanner,
  fileVaultScanner,
  gatekeeperScanner,
  softwareUpdatesScanner,
  kernelExtensionsScanner,
  configurationProfilesScanner,
];
