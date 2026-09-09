from __future__ import annotations

from collections import Counter

from .models import DetectionFinding


SEVERITY_WEIGHT = {"critical": 4, "high": 3, "medium": 2, "low": 1}


def posture_score(findings: list[DetectionFinding]) -> int:
    penalty = sum(SEVERITY_WEIGHT.get(finding.severity, 1) * 4 for finding in findings)
    return max(0, 100 - min(100, penalty))


def summarize(findings: list[DetectionFinding]) -> dict[str, object]:
    severities = Counter(finding.severity for finding in findings)
    techniques = Counter(
        technique
        for finding in findings
        for technique in finding.mitre_techniques
    )
    return {
        "finding_count": len(findings),
        "severity_counts": dict(sorted(severities.items())),
        "mitre_techniques": dict(sorted(techniques.items())),
        "posture_score": posture_score(findings),
    }


def render_markdown(findings: list[DetectionFinding]) -> str:
    summary = summarize(findings)
    lines = [
        "# Synthetic XDR Detection Assessment",
        "",
        "> Generated from synthetic lab telemetry. No production data is used.",
        "",
        f"- Findings: **{summary['finding_count']}**",
        f"- Defensive posture score: **{summary['posture_score']}/100**",
        f"- Severity distribution: `{summary['severity_counts']}`",
        "",
        "## Findings",
        "",
    ]
    if not findings:
        lines.append("No detections matched the supplied telemetry.")
        return "\n".join(lines) + "\n"

    for index, finding in enumerate(findings, 1):
        lines.extend(
            [
                f"### {index}. {finding.title}",
                f"- Rule: `{finding.rule_id}`",
                f"- Severity: **{finding.severity.upper()}**",
                f"- Confidence: **{finding.confidence.upper()}**",
                f"- Device: `{finding.device_id}`",
                f"- Account: `{finding.account}`",
                f"- Evidence IDs: `{', '.join(finding.evidence_event_ids)}`",
                f"- ATT&CK: `{', '.join(finding.mitre_techniques)}`",
                f"- Rationale: {finding.rationale}",
                f"- Remediation: {finding.remediation}",
                "",
            ]
        )
    return "\n".join(lines)
