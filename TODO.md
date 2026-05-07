# NERV-SCAN — Build Backlog

Living checklist. Tick items as we ship them. Ordered by **impact × effort**, not by section.

---

## P0 — Bug fixes in existing scanners

These are wrong today and will produce false positives/negatives on a real Mac.

- [ ] **`core/shell.ts`** — Per-scanner timeout override is supported but unused. Bump to 30s for `softwareupdate -l` and `system_profiler SPApplicationsDataType`.
- [ ] **`core/shell.ts`** — Stop concatenating stderr+stdout in the result; downstream scanners are parsing error text as data.
- [ ] **`core/redact.ts`** — Add patterns: serial number (`[A-Z0-9]{10,12}` from `system_profiler`), UUIDs, email, Apple ID, SSIDs (build dynamically from Wi-Fi scanner output).
- [ ] **`casper/kernelExtensions.ts`** — `kmutil` doesn't exist on macOS < 11. Fall back to `kextstat -kl`. Replace `/com\.apple\./` regex with allowlist for `com.apple.|com.amd.|com.nvidia.`.
- [ ] **`casper/configurationProfiles.ts` / `gatekeeper.ts` / `fileVault.ts`** — Use `result.stdout` only; route stderr + non-zero exit into a `yellow` "scanner unavailable" finding.
- [ ] **`casper/softwareUpdates.ts`** — Switch to `softwareupdate -l --no-scan` with `--plist` output and parse XML; current regex broke after macOS 13.3.
- [ ] **`casper/filevault.ts`** — Add recovery-key audit (`fdesetup haspersonalrecoverykey`); flag yellow if neither personal nor institutional key.
- [ ] **`melchior/applicationFirewall.ts`** — Hard-coded `/usr/libexec/...` path; probe both that and PATH; emit finding if neither exists.
- [ ] **`melchior/sharingServices.ts`** — `haystack.includes(label)` substring-matches (`smb` matches `com.apple.smbd`). Anchor with `\n<label>\b` regex.
- [ ] **`melchior/wifiProfiles.ts`** — Hard-coded `en0`; detect Wi-Fi interface via `networksetup -listallhardwareports`. Add SSIDs to the redaction set.
- [ ] **`melchior/dnsConfiguration.ts`** — DNS always blue. Flag yellow on non-local non-DHCP resolvers; flag orange on `/etc/hosts` redirects to apple.com / icloud.com / github.com / google.com.
- [ ] **`melchior/listeningSockets.ts`** — Classify by port risk (5900 VNC, 6000-6063 X11, 5432/3306/27017 DB, 22 SSH → orange) instead of count thresholds.
- [ ] **`balthasar/screenLock.ts`** — `Number(null)` → NaN bug. Explicit null guard before classifying.
- [ ] **`balthasar/userAccounts.ts`** — Check `dscl . -read /Users/root Password` for `*` (disabled). Flag root-enabled or password-less accounts as red.
- [ ] **`balthasar/launchPersistence.ts`** — Read each plist (`plutil -convert json -o - <path>`); surface `ProgramArguments[0]`, `RunAtLoad`, and code signature of the binary.
- [ ] **`balthasar/loginItems.ts`** — `osascript` needs Automation permission. Detect TCC denial and emit yellow "needs Automation". Switch to parsing `~/Library/Application Support/com.apple.backgroundtaskmanagementagent/BackgroundItems-v*.btm`.
- [ ] **`balthasar/ssh.ts`** — Parse key types; flag RSA<3072 yellow, DSA red. Check `systemsetup -getremotelogin`. Flag `ProxyCommand`/`ProxyJump` in user config.
- [ ] **`balthasar/browserExtensions.ts`** — Read each `Extensions/<id>/<version>/manifest.json`; surface `name` + `permissions`. Add Safari + Firefox.

---

## P0 — Permissions / orchestration

- [ ] **Startup permissions probe**. Detect FDA + Automation grants; mark FDA-required scanners as yellow `"skipped — needs Full Disk Access"` instead of failing silently.
- [ ] **Concurrency cap** in `orchestrator.ts`. Currently all three cores fan out with no upper bound on subprocess count. Cap at 4 concurrent commands.
- [ ] **Per-scanner cancel** in the TUI. Add `Esc` to abort the running scanner; `q` quits the app.
- [ ] **Re-run a single scanner** — `s` on a finding to re-run its scanner. Useful for "did my fix work?"

---

## P1 — Missing CASPER scanners (system / hardware / firmware)

- [ ] **TCC audit** — read `/Library/Application Support/com.apple.TCC/TCC.db` (system) + `~/Library/.../TCC.db` (user). Surface every app with Camera, Microphone, ScreenCapture, Accessibility, FullDiskAccess, InputMonitoring, AppleEvents. **Requires FDA.**
- [ ] **Secure Boot / Startup Security** — `nvram 94b73556-2197-4702-82a8-3e1337dafbfb:AppleSecureBootPolicy` (Intel) or `bputil -d` (Apple Silicon, sudo).
- [ ] **Boot args** — `nvram boot-args` should be empty; `-v`, `-x`, `kcsuffix=development` are red.
- [ ] **Activation Lock** — `system_profiler SPHardwareDataType | grep "Activation Lock"`.
- [ ] **XProtect / MRT versions** — read `/Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Info.plist`; compare to current.
- [ ] **Rapid Security Response** status — `softwareupdate --history`; flag if disabled.
- [ ] **Pending reboots** — uptime vs last security update.
- [ ] **EFI / firmware version** — `system_profiler SPHardwareDataType` Boot ROM Version vs known-good list.
- [ ] **Power-on password** (Intel only) — `firmwarepasswd -check`.
- [ ] **Auto-login** — `defaults read /Library/Preferences/com.apple.loginwindow autoLoginUser`.
- [ ] **Guest account enabled** — `defaults read /Library/Preferences/com.apple.loginwindow GuestEnabled`.
- [ ] **System Extensions** — `systemextensionsctl list` (replaces kexts on modern macOS).
- [ ] **DriverKit extensions** — same call, separate parser.

---

## P1 — Missing MELCHIOR scanners (network / perimeter)

- [ ] **Bluetooth posture** — `system_profiler SPBluetoothDataType`; check Discoverable + paired devices.
- [ ] **AirDrop discoverability** — `defaults read com.apple.sharingd DiscoverableMode`.
- [ ] **Internet Sharing** — `defaults read /Library/Preferences/SystemConfiguration/com.apple.nat`.
- [ ] **Captive portal hijack** — check `/etc/resolver/` for non-default files.
- [ ] **VPN configurations** — `scutil --nc list`.
- [ ] **Proxy settings** — `networksetup -getwebproxy / -getsecurewebproxy / -getsocksfirewallproxy` per interface.
- [ ] **mDNS/Bonjour exposure** — `dns-sd -B _services._dns-sd._udp` (timeout-bounded).
- [ ] **iCloud Private Relay** state — `defaults read com.apple.networkserviceproxy ...`.
- [ ] **Time sync** — `systemsetup -getusingnetworktime` and `-getnetworktimeserver` (default Apple = blue, custom = yellow).
- [ ] **Pf firewall** — surface `/etc/pf.conf` checksum + `pfctl -sr` if root.
- [ ] **Outbound listening (UDP)** — `lsof -nP -iUDP` to complement TCP scanner.
- [ ] **LISTEN-vs-launchd** correlation — flag any LISTEN that doesn't appear in launchd.

---

## P1 — Missing BALTHASAR scanners (identity / persistence / forensics)

- [ ] **Cron jobs** — `crontab -l` per user, plus `/etc/crontab`, `/etc/cron.d/`, `/etc/periodic/`.
- [ ] **at jobs** — `atq`.
- [ ] **emond rules** — `/etc/emond.d/rules/` (deprecated but still loaded).
- [ ] **PAM modules** — checksum `/etc/pam.d/sudo` and `/etc/pam.d/login` (CVE-2017-13872 lineage).
- [ ] **sudoers** — `/etc/sudoers` and `/etc/sudoers.d/*`; flag `NOPASSWD`.
- [ ] **Login/Logout hooks** — `defaults read com.apple.loginwindow LoginHook` / `LogoutHook`.
- [ ] **Periodic scripts** — diff `/etc/periodic/{daily,weekly,monthly}/` against system defaults.
- [ ] **Modern login items** — `BackgroundItems-v*.btm` parser (covered by loginItems fix above).
- [ ] **Shell rc files** — scan `~/.zshrc` `~/.bashrc` `~/.zprofile` `~/.bash_profile` for `eval`, `curl|sh`, base64 decodes.
- [ ] **Recently downloaded executables** — `mdfind "kMDItemContentType == 'public.unix-executable' && kMDItemDateAdded > $time.this_week"`.
- [ ] **Quarantine DB** — sqlite read of `~/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2`.
- [ ] **Keychains** — `security list-keychains`; flag non-default keychains unlocked.
- [ ] **Code-sign LaunchAgents/Daemons** — for each `ProgramArguments[0]`, run `codesign -dv --verbose=4`; flag adhoc-signed or unsigned.
- [ ] **Notification Center extensions** — `pluginkit -mAvvv -p com.apple.usernotifications.banner`.
- [ ] **Safari extensions** — `~/Library/Containers/com.apple.Safari/Data/Library/Safari/Extensions/`.
- [ ] **Firefox extensions** — `~/Library/Application Support/Firefox/Profiles/*/extensions.json`.
- [ ] **iCloud Keychain status** — `security default-keychain`.
- [ ] **Find My / Find My Mac** — `defaults read com.apple.preferences.icloud.plist`.

---

## P2 — Cross-cutting features

- [ ] **Baseline diff mode** (`SYNCHRONIZATION DRIFT`) — save findings to `~/.nerv-scan/baseline.json`; on next run surface `NEW` / `CHANGED` / `RESOLVED`. README promised; not built.
- [ ] **Allowlist / suppress** — `~/.nerv-scan/ignore.json` to permanently dismiss known-good findings (e.g., "yes, I run sshd intentionally").
- [ ] **CIS macOS Benchmark mapping** — add `cis?: string[]` to `Finding`; emit a compliance matrix section in the report.
- [ ] **NIST 800-53 mapping** — same shape, separate field.
- [ ] **SARIF output** — security tooling standard, GitHub code-scanning compatible.
- [ ] **CSV output**.
- [ ] **HTML output** with collapsible sections.
- [ ] **Run history** — write all reports to `~/.nerv-scan/history/` keyed by timestamp.
- [ ] **Unified-log scrape** — `log show --predicate 'subsystem == "com.apple.TCC"' --last 7d` for prompts/denials; `eventMessage CONTAINS "Gatekeeper"` for blocks.
- [ ] **YARA pass** over `~/Downloads`, `/Applications`, LaunchAgents (README roadmap).
- [ ] **Live clock** in `HeaderBar` — currently `formatDate()` runs once at render and freezes.
- [ ] **Filter by pattern** in TUI — `f` cycles red→orange→yellow→all.
- [ ] **Search findings** in TUI — `/` opens a fuzzy-match input.
- [ ] **Markdown report grouping** — `## RED` / `## ORANGE` / `## YELLOW` sections with TOC anchors.

---

## P2 — Hygiene

- [ ] **Tests** — there are zero. Add `vitest` + per-scanner unit tests with mocked `runCommand`.
- [ ] **CI** — typecheck + tests on push. GitHub Actions runner is Linux, so scanners can't run end-to-end; use mocked transcripts captured from a real Mac.
- [ ] **`--scanner <id>`** CLI flag for running one scanner in isolation (already wired in `selectScanners` but no CLI surface).
- [ ] **`--magi <core>`** to run only one core.
- [ ] **`--strict`** that exits non-zero if any orange/red finding (CI gate).
- [ ] **`--json` shorthand** that writes JSON to stdout instead of file.

---

## P3 — Stretch

- [ ] **Real-time mode** — `EndpointSecurity` framework via signed Swift helper (README roadmap).
- [ ] **Privileged helper** for TCC.db / unified log without manual FDA grant — signed Swift helper invoked as a separate binary.
- [ ] **Remediation auto-apply** mode (`--fix`) — opt-in, per-finding, with diff preview before each change.
- [ ] **Web dashboard** — same orchestrator, different transport.

---

## On the current shell approach (reference)

`core/shell.ts` uses `spawn(binary, args, { shell: false })`. Keep it. Reasons:

- No command injection — args never go through a shell parser.
- Mandatory timeout — bash pipelines can't be killed cleanly.
- Structured stdout/stderr/exitCode — pipes lose this.

Do **not** switch to `child_process.exec` or `bash -c "..."`. If a pipeline is needed, do the second stage in JS on the captured stdout.

The one exception to consider: a **signed Swift helper** for things `sudo` can read but a normal user can't (TCC DB, unified log, `pfctl -sr`, `bputil`). That's a separate binary, not a bash invocation.
