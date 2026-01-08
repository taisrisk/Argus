# ARGUS

## Why This Exists

Modern browsers are powerful but opaque. Extensions run with broad permissions, network connections happen invisibly, credentials are stored locally, and users have no visibility into what's actually occurring. Browser credential theft is rampant, with commodity stealers trivially extracting cookies and passwords. When something feels wrong, there's no tool to observe, understand, and protect browser behavior without technical expertise or invasive monitoring software.

## What It Does

Argus is a local, read-only browser security sensor for Windows. It observes browser processes, analyzes extension permissions, monitors network patterns, **detects credential theft attempts**, and correlates behavioral signals into understandable risk assessments. It never blocks legitimate browser operations, modifies data, or executes code—it watches, detects threats, and can respond to confirmed attacks.

## Benefits to Users

**Transparency Without Complexity**: See what your browser extensions can access, what connections are being made, and what processes are accessing your credentials—explained in plain language rather than technical jargon.

**Credential Theft Protection**: Detects when non-browser processes attempt to access cookies, passwords, or authentication tokens. Identifies theft chains before credentials can be exfiltrated.

**Privacy-First Design**: Everything runs locally on your machine. No data leaves your computer, no cloud services, no telemetry. Session logs are stored locally and contain no personal information.

**User-Mode Only, No Drivers**: Unlike other security tools, Argus operates entirely in user-mode with no kernel drivers. This keeps it compatible with anti-cheat systems, lightweight, and legally safer.

**Non-Invasive Observation**: Argus doesn't inject code, hook processes, or intercept traffic. It reads public system information using standard Windows APIs and file monitoring.

**Ephemeral Sessions**: When you close Argus, it's truly gone. No background services, no registry entries, no auto-start configurations. Run it when you want protection, stop it when you don't.

**User Consent Model**: Extension scanning requires explicit opt-in. You control what level of observation happens, and you can decline any scanning you're uncomfortable with.

**Risk Context, Not Verdicts**: Instead of labeling things "malicious" or "safe," Argus explains what it found and why it might matter. You make the decisions based on understandable information.

## The Philosophy

Argus is a sensor with smart response capabilities. It exists to give users visibility into their browser's behavior and protect their credentials from theft, without taking control away from them. It respects privacy, requires consent, leaves no trace (except legitimate threat detections), and trusts users to make informed decisions with clear information.

**Phase 2.6**: Real-time credential theft detection with automatic threat termination. Argus now actively protects your credentials by killing malicious processes before data can be exfiltrated.

---

**Build**: Open `Argus.sln` in Visual Studio, build for x64  
**Run**: `x64\Debug\Argus.exe` or use `run_argus.bat` (run as Administrator for process termination)  
**Phase**: 2.6 - Active defense + automatic threat response
