# ARGUS

**Real-time browser credential protection for Windows with multi-signal EDR mesh.**

## What It Does

Argus detects credential stealers before they can extract browser passwords, cookies, or encryption keys. **Phase 3.1** implements multi-signal correlation where no single watchdog is authoritative - only corroborated signals trigger termination.

### Core Features - Phase 3.1

- **<5ms Detection**: 1ms polling + I/O completion ports for instant threat detection
- **Multi-Signal EDR Mesh**: Handle Monitor | File Identity Tracker | Signal Correlator | ETW
- **Signal Correlation**: No single watchdog is authoritative - requires corroboration
- **Handle + Memory Tracking**: NtReadVirtualMemory detection with context gating
- **Process Suspension**: Freezes threats before termination for forensic analysis
- **Forensic Fingerprinting**: Extracts PE headers, hashes, signatures from suspended processes
- **Smart Whitelisting**: Identifies browser services (elevation_service, updaters) to prevent false positives
- **Intelligent Response**: Suspend → Fingerprint → Correlate → Classify → Terminate/Monitor
- **File Identity Tracking**: Detects symlink/junction/hardlink evasion techniques
- **Continuous Neutralization**: 5-second aggressive scan after termination
- **Extension Monitoring**: Tiered scanning (one-time audit + real-time activity tracking)
- **Multi-Browser Support**: Chrome, Edge, Brave, Opera, Opera GX, Vivaldi, Firefox, Perplexity Comet
- **Configurable Whitelist**: 100+ whitelisted apps in JSON config

### Signal Correlation Logic

**EDR Rule #1**: Any single signal can fail. Only a mesh of signals is authoritative.

**Corroboration Examples:**
- `HandleOpen` + `MemoryRead` = Corroborated
- `FileAccess` + `TempStaging` = Corroborated
- `EncryptionKeyAccess` + `FileAccess` = Corroborated
- `DPAPIAccess` + `MemoryRead` = Corroborated
- `TempStaging` + `NetworkActivity` = Corroborated

**Decision Matrix:**
| Signals | Corroborated | Score | Action |
|---------|--------------|-------|--------|
| 1 | 0 | <30 | Monitor only |
| 2+ | 1+ | 50-74 | Suspend for analysis |
| 3+ | 2+ | 75-99 | Terminate (high confidence) |
| 2+ | 2+ | 100+ | Terminate (confirmed stealer) |

### NtReadVirtualMemory Positioning

**Not used as**:
- Primary kill trigger
- Standalone detection

**Used for**:
- Low-weight signal (+3 risk)
- Corroboration only
- Frequency analysis (repeated reads +5)
- Context: Caller → Target → Browser awareness

**Safe positioning**:
```
NtReadVirtualMemory called: +3 risk
Repeated within 100ms: +5 risk  
Target is browser utility: +8 risk
───────────────────────────────────
By itself: No action
With file access: Corroborated → Suspend
With temp staging: Confirmed → Terminate
```

### Threat Response

| Asset Accessed | Process Type | Action | Latency |
|----------------|-------------|--------|---------|
| Login Data | Same Browser (Self-Access) | Allow (Legitimate) | <1ms |
| Login Data | Browser Service | Log + Monitor | <1ms |
| Login Data | Unknown Process | Suspend → Fingerprint → Kill | <5ms |
| Local State | Same Browser (Self-Access) | Allow (Legitimate) | <1ms |
| Local State | Browser Service | Log + Monitor | <1ms |
| Local State | Unknown Process | Suspend → Fingerprint → Kill | <5ms |
| Cookies (score ≥10) | Same Browser (Self-Access) | Allow (Legitimate) | <1ms |
| Cookies (score ≥10) | Browser Service | Log + Monitor | <1ms |
| Cookies (score ≥10) | Unknown Process | Suspend → Analyze → Kill | <10ms |
| Temp SQLite/JSON | Any | Neutralize + track | <50ms |

**Browser Self-Access**: Browsers accessing their own profile files (e.g., `chrome.exe` accessing `\Google\Chrome\User Data\`) is allowed as legitimate operation for:
- Browser startup
- Sync operations
- Autofill functionality
- Session restoration
- Extension loading

### Technical Details

**Detection**: File identity tracking (file_id, volume_serial) + directory watchers + 1ms polling  
**Prevention**: Process classification → Suspension (NtSuspendProcess) → Forensic extraction → Smart decision  
**Classification**:  
- `BROWSER_CORE`: Main browser executables (chrome.exe, edge.exe, etc.)
- `BROWSER_SERVICE`: Critical browser services (elevation_service.exe, updaters)
- `BROWSER_HELPER`: Processes in browser directories
- `UNKNOWN_THIRD_PARTY`: Unrecognized processes → treated as threats

**Evasion Resistance**: Catches indirect access via symlinks, junctions, hardlinks  
**Extension Scanner**: One-time manifest audit at launch + continuous activity monitoring  

**Build**: `msbuild Argus.sln /p:Configuration=Debug /p:Platform=x64`  
**Run**: `x64\Debug\Argus.exe` (requires Administrator for termination)  
**Phase**: 3.1 - Multi-signal EDR mesh + handle monitoring + signal correlation

### Configuration

**Process Whitelist**: `config/process_whitelist.json`  
- Easily add/remove trusted processes
- Organized by category (browsers, development tools, gaming, etc.)
- Supports wildcards and path patterns

Example:
```json
{
  "categories": {
    "browsers": {
      "processes": ["chrome.exe", "firefox.exe", "brave.exe"]
    },
    "development_tools": {
      "processes": ["devenv.exe", "code.exe", "msbuild.exe"]
    }
  }
}
```

### Architecture

**Multi-Signal EDR Mesh**:
```
[File Identity Tracker] ────┐
[Handle Monitor] ───────────┤
[Memory Read Detector] ─────┼──► Signal Correlator ──► Suspend ──► Classify ──► Verdict
[Temp Staging Detector] ────┤
[Directory Watchers] ───────┤
[ETW Events] ───────────────┘
```

**No single watchdog is authoritative. Requires corroboration.**

**Modular Design**:
- `core/credential_monitor.cpp` - Main coordination
- `core/handle_monitor.cpp` - Cross-process handle tracking + NtReadVirtualMemory
- `core/signal_correlator.cpp` - Multi-signal correlation engine
- `core/file_identity.cpp` - File identity + evasion detection
- `core/process_whitelist.cpp` - Configurable whitelist loader
- `config/process_whitelist.json` - User-editable process list

### Forensic Evidence

```
C:\ProgramData\Argus\forensics\events.log
[2026-01-07T15:23:41Z]
EVENT_ID: 4c92f0a7-3a2e-...
PROCESS: stealer.exe (PID 12345)
ACTION: PASSWORD_FILE_ACCESS
FORENSICS: Process Age 230ms, Parent: powershell.exe, Modules: 8
RESULT: EXTRACTION_PREVENTED
VERIFICATION: 8a4b2c1d
```

### Extension Monitoring

- **Initial Scan**: One-time manifest analysis at launch
- **Flagged Extensions**: Real-time activity monitoring (200ms–2s polling)
- **Whitelisted**: ProtonVPN, NordVPN, ExpressVPN, and other popular VPN extensions

### Privacy

- **Local-only**: No network, no cloud, no telemetry
- **User-mode only**: No kernel drivers or code injection
- **Ephemeral**: No persistence, no registry, no auto-start
- **Consent-based**: Extension scanning requires explicit opt-in
- **Transparent**: All whitelisted processes visible in config file

---

**License**: MIT  
**Platform**: Windows 10/11 x64
