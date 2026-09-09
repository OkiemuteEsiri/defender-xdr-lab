from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any


@dataclass(frozen=True)
class XdrEvent:
    event_id: str
    timestamp: datetime
    device_id: str
    account: str
    event_type: str
    action: str
    process_name: str = ""
    remote_ip: str = ""
    details: dict[str, Any] | None = None

    @classmethod
    def from_dict(cls, record: dict[str, Any]) -> "XdrEvent":
        required = {"event_id", "timestamp", "device_id", "account", "event_type", "action"}
        missing = sorted(required - record.keys())
        if missing:
            raise ValueError(f"missing required fields: {', '.join(missing)}")

        raw_ts = str(record["timestamp"]).replace("Z", "+00:00")
        timestamp = datetime.fromisoformat(raw_ts)
        if timestamp.tzinfo is None:
            timestamp = timestamp.replace(tzinfo=timezone.utc)
        timestamp = timestamp.astimezone(timezone.utc)

        return cls(
            event_id=str(record["event_id"]),
            timestamp=timestamp,
            device_id=str(record["device_id"]),
            account=str(record["account"]),
            event_type=str(record["event_type"]),
            action=str(record["action"]),
            process_name=str(record.get("process_name", "")),
            remote_ip=str(record.get("remote_ip", "")),
            details=dict(record.get("details", {})),
        )


@dataclass(frozen=True)
class DetectionFinding:
    rule_id: str
    title: str
    severity: str
    confidence: str
    device_id: str
    account: str
    evidence_event_ids: tuple[str, ...]
    mitre_techniques: tuple[str, ...]
    rationale: str
    remediation: str
