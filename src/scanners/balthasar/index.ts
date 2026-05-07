import type { Scanner } from '../../core/types.js';
import { userAccountsScanner } from './userAccounts.js';
import { launchPersistenceScanner } from './launchPersistence.js';
import { loginItemsScanner } from './loginItems.js';
import { sshConfigurationScanner } from './sshConfiguration.js';
import { screenLockPolicyScanner } from './screenLockPolicy.js';
import { browserExtensionsScanner } from './browserExtensions.js';

export const balthasarScanners: Scanner[] = [
  userAccountsScanner,
  launchPersistenceScanner,
  loginItemsScanner,
  sshConfigurationScanner,
  screenLockPolicyScanner,
  browserExtensionsScanner,
];
