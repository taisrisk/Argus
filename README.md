# ARGUS

**Local browser security monitor for Windows with active credential theft prevention.**

## What It Does

Argus detects and terminates credential stealers in real-time before they can extract browser passwords, cookies, or encryption keys. Zero-tolerance enforcement with <5ms detection latency.

### Core Features

- **<5ms Detection**: 1ms polling + I/O completion ports for instant threat detection
- **Zero-Tolerance Enforcement**: Login Data/Local State access = immediate termination
- **Forensic Logging**: Tamper-evident event logs with verification hashes
- **File Identity Tracking**: Detects symlink/junction evasion techniques
- **Continuous Neutralization**: 5-second aggressive scan after termination
- **Multi-Browser Support**: Chrome, Edge, Brave, Opera, Vivaldi, Firefox, Comet
- **100+ Whitelisted Apps**: Zero false positives from legitimate software

### Threat Response

| Asset Accessed | Action | Latency |
|----------------|--------|---------|
| Login Data (passwords) | Instant kill | <5ms |
| Local State (master key) | Instant kill | <5ms |
| Cookies (score ≥10) | Kill + scan | <5ms |
| Temp SQLite/JSON | Neutralize + track | <50ms |

### Technical Details

**Detection**: File identity tracking (file_id, volume_serial) + directory watchers + 1ms polling  
**Prevention**: Process termination + 5s continuous file scanning + forensic markers  
**Evasion Resistance**: Catches indirect access via symlinks, junctions, hardlinks  

**Build**: `msbuild Argus.sln /p:Configuration=Debug /p:Platform=x64`  
**Run**: `x64\Debug\Argus.exe` (requires Administrator for termination)  
**Phase**: 2.8.1 - Zero-tolerance enforcement

### Forensic Evidence

```
C:\ProgramData\Argus\forensics\events.log
[2026-01-07T15:23:41Z]
EVENT_ID: 4c92f0a7-3a2e-...
PROCESS: stealer.exe (PID 12345)
ACTION: PASSWORD_FILE_ACCESS
RESULT: EXTRACTION_PREVENTED
VERIFICATION: 8a4b2c1d
```

### Privacy

- **Local-only**: No network, no cloud, no telemetry
- **User-mode only**: No kernel drivers or code injection
- **Ephemeral**: No persistence, no registry, no auto-start
- **Consent-based**: Extension scanning requires explicit opt-in

---

**License**: MIT  
**Platform**: Windows 10/11 x64
