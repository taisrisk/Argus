# ARGUS

**Real-time browser credential protection for Windows with forensic analysis.**

## What It Does

Argus detects credential stealers before they can extract browser passwords, cookies, or encryption keys. Combines process suspension, forensic fingerprinting, and smart whitelisting with <5ms detection.

### Core Features

- **<5ms Detection**: 1ms polling + I/O completion ports for instant threat detection
- **Process Suspension**: Freezes threats before termination for forensic analysis
- **Forensic Fingerprinting**: Extracts PE headers, hashes, signatures from suspended processes
- **Smart Whitelisting**: Identifies browser services (elevation_service, updaters) to prevent false positives
- **Intelligent Response**: Suspend → Fingerprint → Classify → Terminate/Monitor based on process type
- **File Identity Tracking**: Detects symlink/junction/hardlink evasion techniques
- **Continuous Neutralization**: 5-second aggressive scan after termination
- **Extension Monitoring**: Tiered scanning (one-time audit + real-time activity tracking)
- **Multi-Browser Support**: Chrome, Edge, Brave, Opera, Vivaldi, Firefox, Comet
- **Configurable Whitelist**: 100+ whitelisted apps in JSON config

### Threat Response

| Asset Accessed | Process Type | Action | Latency |
|----------------|-------------|--------|---------|
| Login Data | Browser Service | Log + Monitor | <1ms |
| Login Data | Unknown Process | Suspend → Fingerprint → Kill | <5ms |
| Local State | Browser Service | Log + Monitor | <1ms |
| Local State | Unknown Process | Suspend → Fingerprint → Kill | <5ms |
| Cookies (score ≥10) | Browser Service | Log + Monitor | <1ms |
| Cookies (score ≥10) | Unknown Process | Suspend → Analyze → Kill | <10ms |
| Temp SQLite/JSON | Any | Neutralize + track | <50ms |

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
**Phase**: 3.0 - Modular architecture + configurable whitelist

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

**Modular Design**:
- `core/credential_monitor.cpp` - Main coordination (~600 lines)
- `core/process_whitelist.cpp` - Configurable whitelist loader
- `core/threat_detector.h` - Threat detection logic (future)
- `core/monitoring_threads.h` - Background monitoring (future)
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
