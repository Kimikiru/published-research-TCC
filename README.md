# TCC Proactive Detector — Proactive Defense Against TCC Manipulation on macOS

**Status:** research prototype, ~75% complete
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

## Comparison to existing solutions

| Solution | Detection point | Reaction time | Proactive | Detects attack prep |
|---|---|---|---|---|
| AV (Sophos, Defender) | Post-factum | Depends on scan cycle | No | No |
| Jamf Protect | Post-factum | Medium | No | No |
| Built-in macOS | Post-factum | Medium | No | No |
| **This project** | **Pre-factum** | **< 1s (target)** | **Yes** | **Yes** |

## Architecture

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

## Detection algorithm

1. Initialize monitoring modules (process, filesystem, environment, log)
2. Collect process and filesystem events system-wide
3. Correlate events across sources
4. Compute a weighted risk score
5. Decide whether to raise an alert based on score threshold

## Risk scoring model

| Factor | Description | Weight |
|---|---|---|
| Process spawned as root | Potential TCC modification attempt | 0.4 |
| Access to `TCC.db` | Direct interaction with the protected resource | 0.3 |
| Anomalous environment variables | Possible TCC bypass via env-var override | 0.2 |
| Not on process whitelist | Execution of unrecognized binary | 0.1 |

## Current state

- Core module architecture implemented (see above)
- Detection rules and risk scoring model designed and partially implemented
- Prototype demo app functional at ~75% — not yet fully validated against a broader set of simulated attacks
- Target reaction time (<1s) is a design goal; empirical benchmarking is in progress, not yet published

## Roadmap

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
