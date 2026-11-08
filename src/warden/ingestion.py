import json

from pathlib import Path
from pydantic import ValidationError

from warden.models import SecurityEvent

def load_events(filepath: str) -> list[SecurityEvent]:
    events = []
    path = Path(filepath)
    if not path.exists():
        raise FileNotFoundError(filepath)
    with path.open("r", encoding="utf-8") as file:
        for line_num, line in enumerate(file, start=1):
            if not line.strip():
                continue
            try:
                data = json.loads(line)
                event = SecurityEvent.model_validate(data)
                events.append(event)
            except (json.JSONDecodeError, ValidationError) as exc:
                raise ValueError(f"Invalid event on line {line_num}: {exc}") from exc
    
    event_ids = [event.event_id for event in events]
    if len(event_ids) != len(set(event_ids)): 
        raise ValueError("Duplicate event IDs detected.")
    return events