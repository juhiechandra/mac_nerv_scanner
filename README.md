# NERV-SCAN

> *MAGI-driven macOS security audit suite. Three cores deliberate. You read the verdict.*

A read-only macOS security scanner with an interactive React (Ink) TUI styled as a NERV terminal. Modeled on tools like **Lynis**, **Stronghold**, and the **Objective-See** family — but built specifically for macOS, with a streaming finding pipeline, parallel "MAGI" workers, and a `Pattern <colour>` severity scheme inspired by *Neon Genesis Evangelion*.

```
┌─ NERV TERMINAL ── sync ratio 87.4% ──────────────── 2026-05-07 ─┐
│                                                                  │
│   [ MAGI ]                                                       │
│   ╔══ CASPER ══╗  ╔═ MELCHIOR ═╗  ╔═ BALTHASAR ═╗               │
│   ║  ████████  ║  ║  ██████░░  ║  ║  ████░░░░░  ║               │
│   ║  COMPLETE  ║  ║  SCANNING  ║  ║  PENDING    ║               │
│   ╚════════════╝  ╚════════════╝  ╚═════════════╝               │
│                                                                  │
│   ▶ PATTERN ORANGE — Screen lock does NOT require password      │
│                                                                  │
│   AT FIELD: ACTIVE                                               │
└──────────────────────────────────────────────────────────────────┘
```

---

## Quick start

```bash
npm install
npm run dev                  # interactive TUI
npm run dev -- --no-tui      # headless / pipe-friendly
npm run dev -- --redact      # scrub hostname / username / MAC / IP
npm run dev -- --report out.md
npm run dev -- --report out.json
```

Build a standalone runnable:

```bash
npm run build
node dist/cli/main.js
```

`--no-tui` is auto-selected when stdin/stdout are not a TTY (CI, pipes, captured ptys).

Requirements: Node 18+. macOS only (relies on `csrutil`, `fdesetup`, `spctl`, `socketfilterfw`, `dscl`, `defaults`, `launchctl`, `system_profiler`, `kmutil`, `profiles`, `softwareupdate`, `osascript`, `lsof`, `scutil`, `networksetup`, `security`).

---

## Architecture

```
src/
├── cli/              CLI entry + headless runner
├── core/             Engine: types, shell wrapper, finding builder, redaction, orchestrator, registry
├── scanners/
│   ├── casper/       System / hardware / kernel posture
│   ├── melchior/     Network / perimeter / certs
│   └── balthasar/    Identity / persistence / forensic surface
├── reports/          Report builder + Markdown / JSON writer
└── ui/               Ink (React) TUI: theme, components, hooks
```

### Concept: the three MAGI cores

Each scanner declares which MAGI it belongs to. The orchestrator runs the cores in parallel and the scanners *within* a core sequentially, so each core's progress bar moves predictably and you don't fork a hundred subprocesses at once.

| Core | Persona | What it scans |
|---|---|---|
| **CASPER** | the woman / intuition | hardware profile, SIP, FileVault, Gatekeeper, software updates, kernel extensions, MDM profiles |
| **MELCHIOR** | the scientist | application firewall, listening sockets, DNS + `/etc/hosts`, Wi-Fi profiles, sharing services, user-trusted certs |
| **BALTHASAR** | the mother | user accounts, LaunchAgents/Daemons, login items, SSH config, screen-lock policy, browser extensions |

### The Pattern severity model

Each `Finding` carries a `pattern`:

| Pattern | Meaning |
|---|---|
| `blue`   | benign / informational baseline |
| `green`  | non-default but safe |
| `yellow` | review needed |
| `orange` | misconfiguration with security impact |
| `red`    | active threat indicator |

Findings are sorted by severity in the UI (red → blue) and counted in the report's summary table.

### The scanner contract

```ts
interface Scanner {
  id: string;
  title: string;
  magi: 'casper' | 'melchior' | 'balthasar';
  requires?: { fullDiskAccess?: boolean; root?: boolean; network?: boolean };
  run(context: ScanContext): AsyncIterable<Finding>;
}
```

Scanners are async generators. The orchestrator streams findings to the UI as they yield, so the dashboard fills up live during the scan instead of pausing on a `Promise.all`.

### Streaming pipeline

```
scanner.run() ──▶ orchestrator ──▶ events { onProgress, onFinding }
                                    │
                                    ├──▶ Ink useReducer  ──▶ React tree
                                    └──▶ headless writer ──▶ stdout + report
```

Both the TUI hook (`useScanController`) and the headless runner consume the same orchestrator API. The UI is just one of two transports.

### DRY / separation of concerns

- **Scanners** know only how to call shell tools and yield `FindingDraft`s. They never touch React or terminal codes.
- **Core** owns the contract, the runner, and the redaction/severity helpers. Every scanner uses `runCommand`, `buildFinding`, and `classifyByThreshold` so behaviour stays uniform.
- **Reports** consume `Finding[]` and emit Markdown/JSON. They have no knowledge of how the findings were produced.
- **UI** is pure presentation over reducer state. Components don't run scanners; they read state and render.

### Redaction

`--redact` rewrites:

- the user's home directory → `~`
- the username → `[REDACTED]`
- the hostname → `[REDACTED]`
- MAC addresses → `[REDACTED]`
- IPv4 literals → `[REDACTED]`

This is applied at finding-build time *and* to the report header, so even pasted screenshots stay safe.

---

## Scanners catalogue

### CASPER (system / hardware)
| ID | Title | Tool |
|---|---|---|
| `casper.hardware-profile`     | Hardware Profile          | `system_profiler SPHardwareDataType` |
| `casper.sip`                  | System Integrity Protection | `csrutil status` |
| `casper.filevault`            | FileVault Encryption      | `fdesetup status` |
| `casper.gatekeeper`           | Gatekeeper                | `spctl --status` |
| `casper.software-updates`     | Software Updates          | `softwareupdate -l` |
| `casper.kernel-extensions`    | Kernel Extensions         | `kmutil showloaded --list-only` |
| `casper.config-profiles`      | Configuration Profiles (MDM) | `profiles list` |

### MELCHIOR (network / perimeter)
| ID | Title | Tool |
|---|---|---|
| `melchior.application-firewall` | Application Firewall      | `socketfilterfw --getglobalstate` / `--getstealthmode` |
| `melchior.listening-sockets`    | Listening Sockets         | `lsof -nP -iTCP -sTCP:LISTEN` |
| `melchior.dns-configuration`    | DNS & Hosts               | `scutil --dns`, `/etc/hosts` |
| `melchior.wifi-profiles`        | Saved Wi-Fi Networks      | `networksetup -listpreferredwirelessnetworks` |
| `melchior.sharing-services`     | Sharing Services          | `launchctl print-disabled system` |
| `melchior.user-trusted-certs`   | User-Trusted Certificates | `security dump-trust-settings` |

### BALTHASAR (identity / persistence)
| ID | Title | Tool |
|---|---|---|
| `balthasar.user-accounts`      | User Accounts             | `dscl . -read /Groups/admin`, `-list /Users` |
| `balthasar.launch-persistence` | Launch Persistence        | filesystem inspection of `LaunchAgents` / `LaunchDaemons` |
| `balthasar.login-items`        | Login Items               | `osascript "tell application System Events"` |
| `balthasar.ssh`                | SSH Configuration         | `~/.ssh` file inspection |
| `balthasar.screen-lock`        | Screen Lock Policy        | `defaults read com.apple.screensaver` |
| `balthasar.browser-extensions` | Browser Extensions        | per-browser extension directories |

---

## TUI controls

| Key | Action |
|---|---|
| `↑` / `↓` | navigate findings |
| `enter`   | toggle finding detail panel |
| `r`       | write report (after scan completes) |
| `q` / `Ctrl-C` | exit |

---

## Permissions

The scanner is **read-only** and never modifies system state. Some scanners need additional access to surface every signal:

| Capability | Why |
|---|---|
| Full Disk Access | required for unified-log scraping and TCC DB reads (planned) |
| sudo / root      | not used today; kept off the hot path so `nerv-scan` is safe to run as a normal user |

If a tool exits with a permissions error, the orchestrator records a `failed` progress event and continues — one missing data source never aborts the whole scan.

---

## Design notes

- **No comments in source** — function names carry the intent; if a function feels like it needs a comment, it's the wrong shape and gets refactored.
- **`runCommand` is the only shell entry point** — `spawn(..., { shell: false })` with arg arrays, mandatory timeouts. No template strings, no `exec`, no command injection surface.
- **`AsyncIterable` over arrays** — scanners can yield findings as soon as they're computed. The user sees red/orange items pop in within a second; the slow ones (`softwareupdate -l` is an outbound HTTP call) trickle in afterwards.
- **Every scanner is a self-contained module** in its MAGI directory and registered through a single `index.ts`. Adding a scanner is: write `scanners/<core>/<name>.ts`, append to that core's `index.ts`. The orchestrator and UI need no changes.
- **Severity thresholds are values, not branches** — `classifyByThreshold(observed, { yellow, orange, red })` keeps cutoffs declarative.
- **Headless and TUI consume the same orchestrator** — there is exactly one scan implementation; the difference is which side-effect sink consumes the events.

---

## Roadmap

- TCC permissions audit (camera, mic, screen recording, full-disk grants)
- Unified-log scraping for Gatekeeper denials, TCC prompts, auth failures
- Baseline diff mode (`SYNCHRONIZATION DRIFT`) — compare a scan to a stored baseline
- Compliance preset: NIST 800-53 / CIS macOS Benchmark mapping per finding
- Optional YARA pass over `~/Downloads`, `/Applications`, LaunchAgents
- Real-time mode using `EndpointSecurity` via a signed Swift helper

---

## Acknowledgements

Heavy inspiration from prior art:

- **CISOfy/lynis** — audit category structure & remediation patterns
- **drduh/macOS-Security-and-Privacy-Guide** — canonical hardening checklist
- **Objective-See / Patrick Wardle** — KnockKnock, BlockBlock, KextViewr
- **osquery** — schema thinking around system state as queryable data
- **vadimdemedes/ink** — React for the terminal, the foundation of the TUI

`Pattern Orange detected. The fate of destruction is also the joy of rebirth.`
