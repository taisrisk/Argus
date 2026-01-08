# ARGUS

## Why This Exists

Modern browsers are powerful but opaque. Extensions run with broad permissions, network connections happen invisibly, credentials are stored locally, and users have no visibility into what's actually occurring. Browser credential theft is rampant, with commodity stealers trivially extracting cookies and passwords. When something feels wrong, there's no tool to observe, understand, and protect browser behavior without technical expertise or invasive monitoring software.

## What It Does

Argus is a local browser security monitor for Windows with active defense capabilities. It observes browser processes, analyzes extension permissions, monitors network patterns, **detects credential theft attempts in real-time**, and **automatically terminates malicious processes** before data exfiltration can occur.

### Core Features

**Real-Time Credential Theft Detection**: Monitors file system access to browser credential stores (Login Data, Cookies, Local State) using directory watchers. Detects access instantly—no polling delays.

**Automatic Threat Termination**: Processes accessing unencrypted password files (Login Data) are flagged as critical threats and terminated immediately with a risk score of 20+. No human intervention required.

**Comprehensive Whitelist**: 100+ trusted applications excluded from monitoring including all major browsers, development tools, gaming clients, communication apps, media players, and system utilities. Virtually eliminates false positives.

**Multi-Browser Support**: Monitors Chrome, Edge, Brave, Opera, Opera GX, Vivaldi, Perplexity Comet, and Firefox profiles simultaneously.

**Extension Risk Analysis**: Scans for high-risk extension permissions (debugger, proxy, webRequestBlocking) with intelligent filtering of legitimate VPN extensions (ProtonVPN, NordVPN, ExpressVPN, etc.).

**Privacy-First Design**: Everything runs locally. No data leaves your computer, no cloud services, no telemetry. Session logs stored locally contain no personal information.

**User-Mode Only**: No kernel drivers, no code injection, no process hooks. Uses standard Windows APIs (`ReadDirectoryChangesW`, process enumeration) for maximum compatibility.

## Benefits to Users

**Instant Protection**: Credential stealers are terminated within milliseconds of accessing password files—faster than they can extract or transmit data.

**Zero False Positives**: Comprehensive whitelist of 100+ legitimate applications means Argus won't interfere with normal computing activities.

**Transparency Without Complexity**: See exactly which processes accessed credential files, with clear explanations in plain language rather than technical jargon.

**Lightweight & Compatible**: User-mode operation ensures compatibility with anti-cheat systems, no system instability, and minimal resource usage.

**Ephemeral Sessions**: When you close Argus, it's truly gone. No background services, no registry entries, no auto-start. Run it when you want protection, stop when you don't.

**User Consent Model**: Extension scanning requires explicit opt-in. You control observation levels and can decline any scanning.

**Local-Only Logging**: All session logs stored in local `logs/` directory. No network transmission, no cloud storage.

## The Philosophy

Argus is an active defense system that protects browser credentials without taking control away from users. It provides visibility into browser behavior, automatically neutralizes confirmed threats (credential theft), and trusts users to make informed decisions about everything else. It respects privacy, requires consent for scanning, leaves no trace (except legitimate threat detections), and explains findings in understandable terms.

### Threat Response Model

**Automatic Termination** (Score ?10):
- Login Data access: **+20 points** ? Instant kill (unencrypted passwords)
- Cookies + Login Data + Local State: **+20 points** ? Instant kill
- Any 3+ asset types: **+15 points** ? Instant kill

**Manual Review** (Score 5-9):
- Logged as medium/high risk
- User can investigate and take action

**Ignored** (Score <5):
- Low-risk or whitelisted activity
- No alert generated

**Phase 2.6**: Real-time credential theft detection with automatic threat termination. Argus now actively protects your credentials by killing malicious processes before data can be exfiltrated.

---

**Build**: Open `Argus.sln` in Visual Studio, build for x64  
**Run**: `x64\Debug\Argus.exe` or use `run_argus.bat` (run as Administrator for process termination)  
**Phase**: 2.6 - Active defense + automatic threat response

### Whitelisted Applications (100+)

**Browsers**: Chrome, Edge, Firefox, Brave, Opera, Opera GX, Vivaldi, Comet  
**Development**: Visual Studio, VS Code, Git, MSBuild, PowerShell, .NET  
**Graphics**: NVIDIA (all), AMD Radeon, Intel Graphics  
**Hardware**: OpenRGB, FanControl, SteelSeries  
**Communication**: Discord, Slack, Teams, Skype, Zoom, Signal, Telegram  
**Gaming**: Steam, Epic, Origin, Battle.net, Riot, GOG, Wallpaper Engine  
**Media**: Spotify, iTunes, VLC, foobar2000, PotPlayer  
**Utilities**: 7-Zip, WinRAR, Notepad++, GIMP, Photoshop, Blender  
**VPN**: NordVPN, ProtonVPN, ExpressVPN, Surfshark, OpenVPN  
**Antivirus**: Windows Defender, Avast, Avira, Kaspersky, Bitdefender
