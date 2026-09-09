# Defender XDR Detection Engineering Lab

A recruiter-facing defensive security engineering project that demonstrates how Microsoft Defender XDR-style endpoint and identity telemetry can be normalized, correlated, scored, tested, and converted into auditable investigation findings.

> **Safety boundary:** this repository uses synthetic telemetry only. It does not connect to a live Microsoft tenant, contain customer data, deploy response actions, or claim that a detection proves compromise.

## Problem statement

XDR platforms produce large volumes of endpoint, identity, process, authentication, and security-control telemetry. The engineering challenge is not merely collecting events; it is turning them into explainable detections that preserve evidence, support investigation, minimize false positives, and produce actionable remediation guidance.

This lab implements that workflow locally using Python and a synthetic Defender XDR-style dataset.

## What this project demonstrates

- Defensive detection engineering
- XDR telemetry normalization
- Behavioral correlation across events
- Evidence-preserving findings
- MITRE ATT&CK mapping
- Severity and confidence separation
- Investigator-oriented remediation guidance
- Synthetic security-data design
- Unit-test-driven detection validation
- CI-based regression testing
- Executive-style security reporting

## Architecture

```text
Synthetic XDR JSON
        |
        v
Input validation / UTC normalization
        |
        v
Immutable XdrEvent model
        |
        +-------------------+
        |                   |
        v                   v
Behavioral rules       Correlation rules
        |                   |
        +---------+---------+
                  v
          DetectionFinding
                  |
                  v
      ATT&CK / severity / evidence
                  |
                  v
        Markdown assessment report
```

See [`docs/architecture.md`](docs/architecture.md) for component boundaries, trust boundaries, and production extension points.

## Implemented detections

| Rule | Analytic | Severity | ATT&CK | Purpose |
|---|---|---:|---|---|
| `XDR-001` | Suspicious PowerShell execution | High | T1059.001 | Identifies encoded or hidden PowerShell characteristics for investigation |
| `XDR-002` | Endpoint security control impairment | Critical | T1562.001 | Identifies endpoint-protection disablement or tamper attempts |
| `XDR-003` | Remote logon fan-out | High | T1021, T1078 | Correlates one identity authenticating to multiple devices in a short window |

These mappings provide defensive behavioral context. They do not assert adversary attribution or successful exploitation.

## Repository structure

```text
.github/workflows/ci.yml          # Least-privilege CI
src/models.py                     # Canonical event/finding models
src/detections.py                 # Defensive analytics
src/reporting.py                  # Metrics and Markdown reporting
src/main.py                       # CLI assessment entry point
data/synthetic_xdr_events.json    # Clearly labeled synthetic telemetry
tests/test_detections.py          # Positive/negative/correlation tests
docs/architecture.md              # Technical architecture
docs/methodology.md               # Detection, triage, remediation methodology
reports/example-assessment.md      # Example executive-style output
```

## Usage

Requires Python 3.11+ and uses only the standard library.

```bash
python -m unittest discover -s tests -v
python -m src.main data/synthetic_xdr_events.json --output reports/generated-assessment.md
```

The CLI validates input records, rejects duplicate event IDs, normalizes timestamps to UTC, runs all detections, and generates a Markdown assessment.

## Detection engineering methodology

The project follows a simple detection lifecycle:

1. Define the security behavior of interest.
2. Identify the telemetry required to observe it.
3. Normalize evidence into a stable schema.
4. Implement explainable analytics with explicit thresholds.
5. Test both matching and non-matching behavior.
6. Preserve the source event IDs behind every finding.
7. Document triage, remediation, and false-positive considerations.
8. Revalidate after tuning or control changes.

Detailed methodology is in [`docs/methodology.md`](docs/methodology.md).

## Validation strategy

The unit suite validates:

- encoded PowerShell positive detection
- benign PowerShell negative behavior
- critical classification for protection impairment
- remote-logon correlation across distinct devices
- below-threshold negative behavior
- source evidence ID preservation
- bounded posture scoring
- finding/severity aggregation

CI also performs a synthetic end-to-end report-generation smoke test.

## Reporting design

Findings intentionally separate:

- **severity** — potential security impact
- **confidence** — strength of the analytic signal
- **evidence** — event IDs that caused the match
- **ATT&CK context** — relevant defensive technique mapping
- **rationale** — why the analytic matched
- **remediation** — next investigative or corrective action

This avoids treating a behavioral match as proof of malicious activity.

## Remediation and revalidation workflow

Typical workflow:

1. Validate data completeness and timestamps.
2. Confirm whether activity corresponds to an approved administrative action.
3. Pivot into surrounding endpoint, identity, authentication, and network telemetry.
4. Contain or restrict only when evidence supports unauthorized activity.
5. Restore impaired controls where appropriate.
6. Re-run approved test telemetry after tuning or remediation.
7. Confirm the expected detection still fires while known-benign activity does not.

## Design decisions

### Explainability over opaque scoring
Each rule has explicit matching logic and evidence IDs. Reviewers can understand why a finding exists.

### Correlation instead of single-event dependence
The remote-logon analytic demonstrates how several individually legitimate events can become suspicious when correlated by account, device count, and time window.

### Synthetic data by design
The dataset demonstrates realistic engineering structure without exposing employer, customer, or tenant information.

### Vendor-shaped, not vendor-locked
The schema is inspired by common Defender XDR investigation concepts, but the code remains local and portable.

## Limitations

This is a portfolio lab, not a production SOC platform. It intentionally excludes:

- live Defender XDR API integration
- real tenant credentials
- automated host isolation or account disablement
- production threat-intelligence feeds
- advanced entity graphs
- environment-specific baselining
- machine-learning classification
- large-scale event streaming

Thresholds and control logic would require tuning before operational deployment.

## Skills demonstrated

**Detection Engineering:** rule design, behavioral analytics, ATT&CK alignment, correlation, false-positive awareness.

**Incident Response:** evidence preservation, triage sequencing, remediation guidance, revalidation.

**Security Engineering:** schema validation, deterministic processing, testable modules, least-privilege CI.

**Python:** dataclasses, UTC normalization, CLI design, aggregation, Markdown reporting, standard-library testing.

**Risk Communication:** explicit severity/confidence, limitations, executive-style reporting, non-overstated conclusions.

## Roadmap

- add synthetic identity-risk and device-risk enrichment
- add detection coverage matrix and rule metadata registry
- add configurable thresholds through YAML/JSON policy
- add incident timeline correlation
- add benign-baseline fixtures for regression testing
- add ATT&CK coverage export suitable for Navigator workflows
- add optional authorized API adapter interface without embedding credentials

## Ethical use

This repository is intended for defensive engineering, learning, and authorized security validation. It contains no exploit automation, credential theft, persistence, command-and-control implementation, malware, or production targeting.
