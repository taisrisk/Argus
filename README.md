# ARGUS

**Real-time browser credential protection for Windows.**

## What It Does

Detects and stops credential stealers before they can extract passwords, cookies, or encryption keys. Uses multi-signal correlation to eliminate false positives—multiple signals must corroborate before action is taken.

## Key Features

- **<5ms Detection**: Real-time monitoring via I/O completion ports
- **Multi-Signal Mesh**: Correlates handle activity, file access, memory reads, and temp staging
- **Process Suspension**: Freezes threats before termination for forensic analysis
- **Evasion Resistant**: Detects symlink, junction, and hardlink attacks
- **Smart Whitelisting**: Distinguishes browser self-access from threats
- **Multi-Browser**: Chrome, Edge, Brave, Firefox, Vivaldi, Opera, and more
- **Local-Only**: No network, cloud, or telemetry

## How It Works

**Signal Correlation**: No single signal is authoritative. Threats are classified based on combined evidence:
- Single signal: Monitor only
- 2+ corroborated signals: Suspend for analysis
- Multiple confirmed signals: Terminate with high confidence

**Process Classes**:
- `BROWSER_CORE`: Main browser executables
- `BROWSER_SERVICE`: Browser services (updaters, elevation_service)
- `UNKNOWN_THIRD_PARTY`: Unrecognized processes → treated as threats

**Legitimate Browser Access** (automatically allowed):
- Browsers accessing their own profile files
- Sync operations, autofill, session restoration

## Setup

**Build**: `msbuild Argus.sln /p:Configuration=Debug /p:Platform=x64`  
**Run**: `x64\Debug\Argus.exe` (requires Administrator)

**Configure**: Edit `config/process_whitelist.json` to add trusted processes

```json
{
  "categories": {
    "browsers": {
      "processes": ["chrome.exe", "firefox.exe", "brave.exe"]
    }
  }
}
```

## Architecture

Multi-signal detection flow:
```
File Monitor ────┐
Handle Monitor ──┼──► Signal Correlator ──► Suspend ──► Classify ──► Verdict
Memory Detector ─┤
Temp Staging ────┘
```

---

**License**: MIT  
**Platform**: Windows 10/11 x64
