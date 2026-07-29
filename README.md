# TCC Proactive Detector — Proactive Defense Against TCC Manipulation on macOS

**Status:** early-stage research prototype — individual monitoring components implemented and independently functional; end-to-end detection pipeline not yet wired together
**Platform:** macOS 15–26
**Language:** Swift
**Domain:** macOS endpoint security / blue team
**Author:** Mikhail Nikolaev ([@kimi_dev](https://t.me/kimi_dev))

## Abstract

macOS uses the **Transparency, Consent & Control (TCC)** subsystem to gate application access to sensitive resources — camera, microphone, user files, Full Disk Access. All existing defenses (built-in macOS protections, Jamf Protect, endpoint AV like Sophos/Defender) act **reactively**: they detect that `TCC.db` was already modified, after the fact.

This project explores a **proactive** detection approach: instead of waiting for the database to change, it monitors precursor signals — privileged process spawns, anomalous environment variables, filesystem events around the TCC database path — and raises risk-scored alerts before the manipulation completes.

It directly targets two MITRE ATT&CK sub-techniques on macOS:

| Technique | Name |
|---|---|
| [T1548.006](https://attack.mitre.org/techniques/T1548/006/) | Abuse Elevation Control Mechanism: TCC Manipulation |
| T1548.005 | Abuse Elevation Control Mechanism: Temporary Elevated Cloud Access |

## Motivation

Public documentation and vendor tooling confirm the gap this project targets: existing solutions detect TCC abuse post-factum rather than intercepting the setup phase (privilege escalation attempts, env-var based TCC database overrides on systems without SIP, Finder-based AppleScript abuse with inherited FDA, etc.). No current consumer or enterprise tool correlates these precursor signals into a pre-emptive alert.

## Threat model

Attackers can manipulate the TCC database through several documented vectors:
- Abusing privileged system apps (e.g. Finder, which has FDA by default) to execute unprompted AppleScript
- Overriding the TCC database via environment variables + `launchctl` on systems with SIP disabled
- Process injection into applications that already hold the desired TCC grants

The hypothesis this project tests: if these precursor behaviors are monitored and correlated in real time, manipulation attempts can be flagged and blocked *before* `TCC.db` is actually altered — closing the detection gap left by reactive tools.

> Current build monitors a local test database (`TCC_test.db`) and a test directory rather than the real system `/Library/Application Support/com.apple.TCC/TCC.db`. Reading the real path requires Full Disk Access entitlement and interacts with SIP; the test stand-in lets the detection logic be validated in isolation before that integration step.

## Comparison to existing solutions

| Solution | Detection point | Reaction time | Proactive | Detects attack prep |
|---|---|---|---|---|
| AV (Sophos, Defender) | Post-factum | Depends on scan cycle | No | No |
| Jamf Protect | Post-factum | Medium | No | No |
| Built-in macOS | Post-factum | Medium | No | No |
| **This project** | **Pre-factum** | **< 1s (target)** | **Yes** | **Yes** |

## Architecture (target design)

```
TCC proactive detector
├── Core
│   ├── AlertCenter          — alert dispatch
│   ├── EnvInspector         — anomalous environment variable detection
│   ├── FSEventsMonitor      — filesystem event monitoring around TCC.db
│   ├── LogMonitor           — system log correlation
│   ├── ProcessMonitor       — process spawn / privilege monitoring
│   ├── RiskEngine           — weighted risk scoring
│   ├── RuleEngine           — detection rule evaluation
│   └── TCCSnapshotManager   — periodic TCC.db state snapshots
├── Models
│   ├── ProcessInfo
│   ├── RiskEvent
│   ├── SecurityEvent
│   └── TCCSnapshot
├── Storage
│   └── EventStorage
└── UI
    ├── DashboardView
    ├── EventDetailView
    └── TimelineView
```

This is the design the project is working toward. Implementation status per component below.

## Implementation status

| Component | State | Notes |
|---|---|---|
| `ProcessMonitor` | **Implemented** | Polls running processes every second, tracks a PID baseline, flags spawns matching known-suspicious commands (`osascript`, `sudo`, `tccutil`) |
| `FSEventsMonitor` | **Implemented** | Wired to the native FSEvents API, watches a target directory and classifies create/modify/delete/rename events |
| `TCCSnapshotManager` | **Implemented (test DB)** | Reads/diffs entries via SQLite3 against a local test database standing in for the real `TCC.db` |
| `RuleEngine` | **Stub** | Placeholder scoring logic (two hardcoded string checks); not the weighted model described below |
| `RiskEngine` | **Not wired** | The intended weighted-scoring struct exists in code but isn't connected to any monitor's output yet |
| `AlertCenter` | **Stub** | Dispatches a console message; no real alerting pipeline yet |
| `EnvInspector`, `LogMonitor` | **Not started** | |
| `Models`, `Storage`, `UI` | **Not started** | |
| End-to-end pipeline (monitor → correlate → score → alert) | **Not connected** | Monitors currently print detections directly; nothing routes through `RuleEngine`/`RiskEngine`/`AlertCenter` yet |

## Detection algorithm (target)

1. Initialize monitoring modules (process, filesystem, environment, log)
2. Collect process and filesystem events system-wide
3. Correlate events across sources
4. Compute a weighted risk score
5. Decide whether to raise an alert based on score threshold

Steps 1–2 are implemented per-monitor; steps 3–5 (correlation, scoring, alerting) are designed but not yet connected to live monitor output.

## Risk scoring model (target)

| Factor | Description | Weight |
|---|---|---|
| Process spawned as root | Potential TCC modification attempt | 0.4 |
| Access to `TCC.db` | Direct interaction with the protected resource | 0.3 |
| Anomalous environment variables | Possible TCC bypass via env-var override | 0.2 |
| Not on process whitelist | Execution of unrecognized binary | 0.1 |

This weighting scheme exists in code as a standalone struct but is not yet fed by monitor output — see Implementation status above.

## Roadmap

- Wire `ProcessMonitor` / `FSEventsMonitor` output into `RuleEngine` → `RiskEngine` → `AlertCenter` as an actual pipeline
- Replace the `TCC_test.db` / test-directory stand-ins with the real system path, gated on Full Disk Access entitlement
- Implement `EnvInspector`, `LogMonitor`, and the `Models`/`Storage`/`UI` layers
- Extend monitoring to additional protected system tables beyond `TCC.db`
- Add ML-based prediction of attack likelihood from correlated signal history
- Package for integration into enterprise macOS security monitoring stacks

## References

- Apple Platform Security — Transparency, Consent, and Control (TCC)
- Apple Developer Documentation — Security and Privacy
- Apple Developer Documentation — File System Events
- MITRE ATT&CK — [T1548.006: TCC Manipulation](https://attack.mitre.org/techniques/T1548/006/)
- MITRE ATT&CK — T1548.005: Temporary Elevated Cloud Access
- Jamf Protect Documentation
- Sophos Endpoint Documentation
- NIST SP 800-92 — Guide to Computer Security Log Management
- OWASP Logging Cheat Sheet

---

*This project originated as a school-level information security research project (10th grade, blue-team direction) and is published here as an ongoing independent research effort.*
