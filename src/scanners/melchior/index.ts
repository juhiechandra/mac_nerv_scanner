import type { Scanner } from '../../core/types.js';
import { applicationFirewallScanner } from './applicationFirewall.js';
import { listeningSocketsScanner } from './listeningSockets.js';
import { dnsConfigurationScanner } from './dnsConfiguration.js';
import { wifiProfilesScanner } from './wifiProfiles.js';
import { sharingServicesScanner } from './sharingServices.js';
import { userTrustedCertificatesScanner } from './userTrustedCertificates.js';

export const melchiorScanners: Scanner[] = [
  applicationFirewallScanner,
  listeningSocketsScanner,
  dnsConfigurationScanner,
  wifiProfilesScanner,
  sharingServicesScanner,
  userTrustedCertificatesScanner,
];
