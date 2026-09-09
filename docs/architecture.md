# Architecture

## Purpose

This project demonstrates a defensive XDR analytics workflow using synthetic endpoint and identity telemetry. It is intentionally vendor-shaped rather than vendor-dependent: the event model resembles common Microsoft Defender XDR investigation fields, while the detection engine remains local and deterministic.

## Components

1. **Telemetry ingestion** — `src/main.py` loads JSON records and rejects malformed or duplicate event identifiers.
2. **Normalization** — `src/models.py` converts records into immutable UTC-normalized `XdrEvent` objects.
3. **Detection analytics** — `src/detections.py` contains independent behavioral rules for suspicious PowerShell, endpoint-control impairment, and remote-logon fan-out.
4. **Evidence preservation** — every finding contains the event IDs that caused the match so a reviewer can trace a conclusion back to source telemetry.
5. **Reporting** — `src/reporting.py` aggregates severity, ATT&CK technique coverage, posture scoring, and investigator-facing remediation guidance.
6. **Validation** — `tests/` exercises positive matches, negative matches, correlation thresholds, evidence preservation, and score boundaries.

## Trust boundaries

- Input telemetry is treated as untrusted data and is schema-validated before analysis.
- A detection match is treated as an investigative lead, not proof of compromise.
- ATT&CK mappings describe behavioral context and do not assert attacker attribution.
- Synthetic data is isolated under `data/`; the project does not connect to live Defender tenants or APIs.

## Production extension points

A production implementation could replace local JSON input with authorized Defender XDR APIs, introduce a schema registry, enrich device/account context from CMDB or identity sources, persist findings to a case-management platform, and version detections as code. Those integrations are deliberately excluded here because this portfolio project contains no production credentials or customer telemetry.
