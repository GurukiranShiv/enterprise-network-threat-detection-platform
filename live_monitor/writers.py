from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Iterable, List


def append_jsonl(path: str | Path, item: Dict[str, Any]) -> None:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("a", encoding="utf-8") as f:
        f.write(json.dumps(item, ensure_ascii=False) + "\n")


def atomic_write_json(path: str | Path, data: Any) -> None:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(p.suffix + ".tmp")
    tmp.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
    tmp.replace(p)


def read_json_list(path: str | Path) -> List[Dict[str, Any]]:
    p = Path(path)
    if not p.exists():
        return []
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
        return data if isinstance(data, list) else []
    except Exception:
        return []


def write_alerts(path: str | Path, alerts: Iterable[Dict[str, Any]], max_alerts: int = 500) -> None:
    items = list(alerts)
    items = items[-max_alerts:]
    # Newest first for dashboards.
    items = sorted(items, key=lambda x: x.get("timestamp", ""), reverse=True)
    atomic_write_json(path, items)
