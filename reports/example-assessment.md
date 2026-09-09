# Example XDR Detection Assessment

> Synthetic portfolio example. No production or employer/client telemetry is represented.

## Executive summary

The synthetic assessment generated three investigation leads from six XDR-style events. The highest-priority issue was an endpoint-protection tamper event, followed by encoded PowerShell execution and rapid remote-logon fan-out from one service identity.

## Findings

| Rule | Finding | Severity | ATT&CK | Validation focus |
|---|---|---:|---|---|
| XDR-002 | Endpoint security control impairment | Critical | T1562.001 | Change authorization, initiating process, control restoration |
| XDR-001 | Suspicious PowerShell execution | High | T1059.001 | Parent/child process chain, user intent, script provenance |
| XDR-003 | Remote logon fan-out | High | T1021, T1078 | Administrative scope, source host, identity legitimacy |

## Recommended remediation sequence

1. Validate and restore endpoint security controls on the affected workstation.
2. Review the PowerShell process lineage and related identity/network telemetry.
3. Confirm whether the service account's multi-host authentication pattern is approved administration or automation.
4. Restrict or reset identities only when investigation establishes unauthorized use.
5. Replay approved synthetic test cases after tuning to confirm detection coverage remains intact.

## Residual risk

A detection match is not proof of compromise. Residual risk depends on evidence quality, surrounding telemetry, control state, identity privilege, and whether observed activity can be attributed to authorized operations.
