from pathlib import Path
from typing import List, Dict, Any
import json


def load_suricata_eve(input_dir: str) -> List[Dict[str, Any]]:
    path = Path(input_dir) / "suricata_eve.json"
    if not path.exists():
        return []
    events = []
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return events
