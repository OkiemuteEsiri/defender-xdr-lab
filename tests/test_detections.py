from __future__ import annotations

import unittest
from datetime import datetime, timezone

from src.detections import (
    detect_control_impairment,
    detect_remote_logon_fanout,
    detect_suspicious_powershell,
    run_all_detections,
)
from src.models import XdrEvent
from src.reporting import posture_score, summarize


def event(event_id: str, *, event_type: str, action: str, device: str = "host-1", account: str = "LAB\\user", process: str = "", details=None, minute: int = 0) -> XdrEvent:
    return XdrEvent(
        event_id=event_id,
        timestamp=datetime(2026, 9, 9, 9, minute, tzinfo=timezone.utc),
        device_id=device,
        account=account,
        event_type=event_type,
        action=action,
        process_name=process,
        details=details or {},
    )


class DetectionTests(unittest.TestCase):
    def test_encoded_powershell_matches(self):
        findings = detect_suspicious_powershell([
            event("1", event_type="process", action="created", process="powershell.exe", details={"command_line": "powershell.exe -EncodedCommand TEST"})
        ])
        self.assertEqual(1, len(findings))
        self.assertEqual("T1059.001", findings[0].mitre_techniques[0])

    def test_benign_powershell_does_not_match(self):
        findings = detect_suspicious_powershell([
            event("1", event_type="process", action="created", process="powershell.exe", details={"command_line": "powershell.exe Get-Date"})
        ])
        self.assertEqual([], findings)

    def test_control_tamper_is_critical(self):
        findings = detect_control_impairment([
            event("2", event_type="security_control", action="tamper_attempt")
        ])
        self.assertEqual("critical", findings[0].severity)

    def test_remote_logon_fanout_requires_distinct_devices(self):
        events = [
            event("3", event_type="remote_logon", action="success", device="a", account="LAB\\svc", minute=0),
            event("4", event_type="remote_logon", action="success", device="b", account="LAB\\svc", minute=4),
            event("5", event_type="remote_logon", action="success", device="c", account="LAB\\svc", minute=8),
        ]
        findings = detect_remote_logon_fanout(events)
        self.assertEqual(1, len(findings))
        self.assertEqual(3, len(findings[0].evidence_event_ids))

    def test_remote_logon_below_threshold_does_not_match(self):
        events = [
            event("3", event_type="remote_logon", action="success", device="a", account="LAB\\svc", minute=0),
            event("4", event_type="remote_logon", action="success", device="b", account="LAB\\svc", minute=4),
        ]
        self.assertEqual([], detect_remote_logon_fanout(events))

    def test_all_detections_preserve_evidence_ids(self):
        findings = run_all_detections([
            event("9", event_type="security_control", action="disabled")
        ])
        self.assertEqual(("9",), findings[0].evidence_event_ids)

    def test_posture_score_is_bounded(self):
        findings = [detect_control_impairment([event(str(i), event_type="security_control", action="disabled")])[0] for i in range(10)]
        self.assertGreaterEqual(posture_score(findings), 0)
        self.assertLessEqual(posture_score(findings), 100)

    def test_summary_counts_findings(self):
        findings = detect_control_impairment([event("2", event_type="security_control", action="disabled")])
        summary = summarize(findings)
        self.assertEqual(1, summary["finding_count"])
        self.assertEqual(1, summary["severity_counts"]["critical"])


if __name__ == "__main__":
    unittest.main()
