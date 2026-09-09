from __future__ import annotations

import argparse
import json
from pathlib import Path

from .detections import run_all_detections
from .models import XdrEvent
from .reporting import render_markdown


def load_events(path: Path) -> list[XdrEvent]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, list):
        raise ValueError("telemetry input must be a JSON array")
    events = [XdrEvent.from_dict(record) for record in payload]
    event_ids = [event.event_id for event in events]
    if len(event_ids) != len(set(event_ids)):
        raise ValueError("event_id values must be unique")
    return events


def main() -> int:
    parser = argparse.ArgumentParser(description="Assess synthetic Microsoft Defender XDR-style telemetry")
    parser.add_argument("input", type=Path, help="Path to synthetic JSON telemetry")
    parser.add_argument("--output", type=Path, default=Path("reports/generated-assessment.md"))
    args = parser.parse_args()

    events = load_events(args.input)
    findings = run_all_detections(events)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(render_markdown(findings), encoding="utf-8")
    print(f"events={len(events)} findings={len(findings)} report={args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
