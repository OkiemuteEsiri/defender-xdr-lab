from __future__ import annotations

from collections import defaultdict
from datetime import timedelta

from .models import DetectionFinding, XdrEvent


SUSPICIOUS_POWERSHELL_TOKENS = ("-enc", "-encodedcommand", "-windowstyle hidden")


def detect_suspicious_powershell(events: list[XdrEvent]) -> list[DetectionFinding]:
    findings: list[DetectionFinding] = []
    for event in events:
        if event.event_type != "process":
            continue
        command_line = str((event.details or {}).get("command_line", "")).lower()
        if event.process_name.lower() in {"powershell.exe", "pwsh.exe"} and any(
            token in command_line for token in SUSPICIOUS_POWERSHELL_TOKENS
        ):
            findings.append(
                DetectionFinding(
                    rule_id="XDR-001",
                    title="Suspicious PowerShell execution",
                    severity="high",
                    confidence="medium",
                    device_id=event.device_id,
                    account=event.account,
                    evidence_event_ids=(event.event_id,),
                    mitre_techniques=("T1059.001",),
                    rationale="PowerShell used encoded or hidden execution characteristics that merit investigation.",
                    remediation="Validate administrative intent, review the parent/child process chain, and isolate the device if malicious activity is confirmed.",
                )
            )
    return findings


def detect_control_impairment(events: list[XdrEvent]) -> list[DetectionFinding]:
    findings: list[DetectionFinding] = []
    for event in events:
        if event.event_type == "security_control" and event.action in {"disabled", "tamper_attempt"}:
            findings.append(
                DetectionFinding(
                    rule_id="XDR-002",
                    title="Endpoint security control impairment",
                    severity="critical",
                    confidence="high",
                    device_id=event.device_id,
                    account=event.account,
                    evidence_event_ids=(event.event_id,),
                    mitre_techniques=("T1562.001",),
                    rationale="Endpoint protection was disabled or a tamper attempt was recorded.",
                    remediation="Confirm change authorization, restore protection, inspect surrounding telemetry, and investigate the initiating identity.",
                )
            )
    return findings


def detect_remote_logon_fanout(events: list[XdrEvent], threshold: int = 3, minutes: int = 15) -> list[DetectionFinding]:
    grouped: dict[str, list[XdrEvent]] = defaultdict(list)
    for event in events:
        if event.event_type == "remote_logon" and event.action == "success":
            grouped[event.account].append(event)

    findings: list[DetectionFinding] = []
    window = timedelta(minutes=minutes)
    for account, account_events in grouped.items():
        ordered = sorted(account_events, key=lambda event: event.timestamp)
        for index, start in enumerate(ordered):
            relevant = [
                event for event in ordered[index:]
                if event.timestamp - start.timestamp <= window
            ]
            devices = {event.device_id for event in relevant}
            if len(devices) >= threshold:
                findings.append(
                    DetectionFinding(
                        rule_id="XDR-003",
                        title="Remote logon fan-out",
                        severity="high",
                        confidence="medium",
                        device_id=start.device_id,
                        account=account,
                        evidence_event_ids=tuple(event.event_id for event in relevant),
                        mitre_techniques=("T1021", "T1078"),
                        rationale=f"Account authenticated successfully to {len(devices)} devices within {minutes} minutes.",
                        remediation="Confirm whether the activity matches approved administration, review source infrastructure, and reset or restrict the account if unauthorized.",
                    )
                )
                break
    return findings


def run_all_detections(events: list[XdrEvent]) -> list[DetectionFinding]:
    findings = []
    findings.extend(detect_suspicious_powershell(events))
    findings.extend(detect_control_impairment(events))
    findings.extend(detect_remote_logon_fanout(events))
    return sorted(findings, key=lambda finding: (finding.severity, finding.rule_id), reverse=True)
