# Methodology

## Detection lifecycle

The lab follows a simple engineering lifecycle: define behavior of interest, identify required telemetry, normalize evidence, implement an explainable analytic, test positive and negative cases, document triage guidance, and revalidate after tuning.

## Analytics

### XDR-001 — Suspicious PowerShell execution
Flags encoded or hidden PowerShell execution characteristics. This is a behavioral lead, not a malware verdict. ATT&CK: T1059.001.

### XDR-002 — Endpoint security control impairment
Flags disablement or tamper-attempt events affecting endpoint protection. ATT&CK: T1562.001.

### XDR-003 — Remote logon fan-out
Correlates one account successfully authenticating to at least three distinct devices within fifteen minutes. ATT&CK: T1021 and T1078.

## Triage workflow

1. Validate timestamp, device, identity, and event completeness.
2. Confirm whether the activity maps to an approved operational change or administrative task.
3. Pivot across surrounding endpoint, identity, process, network, and authentication telemetry.
4. Compare against the account's expected administration scope and source infrastructure.
5. Escalate only when the evidence supports suspicious or malicious activity.
6. Preserve event IDs and investigative notes so findings remain auditable.

## Remediation and validation

- For suspicious script execution, validate the parent/child process tree, user intent, script provenance, and related network activity.
- For protection impairment, restore the control, confirm tamper protection, review administrative changes, and inspect the initiating process/account.
- For remote-logon fan-out, verify the management source, privilege level, target population, and whether the sequence matches an approved automation pattern.
- After remediation, replay equivalent synthetic telemetry or approved test events and verify that the expected detection still fires while known-benign activity remains below threshold.

## Scoring

The posture score is deliberately simple and transparent. Findings apply bounded severity-weighted penalties to a 100-point baseline. It is intended for lab comparison and reporting, not as a substitute for organizational risk models.

## Limitations

The synthetic dataset is small and deterministic. There is no live Microsoft Defender integration, threat-intelligence enrichment, entity graph, machine-learning model, or production response automation. Thresholds would require environment-specific tuning before operational use.
