import math
import ipaddress
from datetime import datetime, timezone
from typing import Iterable, List, Dict, Any


def parse_ts(value: str) -> float:
    try:
        return float(value)
    except Exception:
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()
        except Exception:
            return 0.0


def epoch_to_iso(ts: float) -> str:
    try:
        return datetime.fromtimestamp(float(ts), tz=timezone.utc).isoformat()
    except Exception:
        return datetime.now(timezone.utc).isoformat()


def is_internal_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return addr.is_private or ip.startswith("10.") or ip.startswith("192.168.") or ip.startswith("172.16.")
    except Exception:
        return False


def shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    counts = {}
    for ch in text:
        counts[ch] = counts.get(ch, 0) + 1
    total = len(text)
    return -sum((count / total) * math.log2(count / total) for count in counts.values())


def severity_from_score(score: int) -> str:
    """Three-level production severity used by the live dashboard.

    Normal is reserved for observed telemetry that did not become an alert.
    Any emitted alert is at least High unless the score is below 50.
    """
    if score >= 85:
        return "Critical"
    if score >= 50:
        return "High"
    return "Normal"


def group_by(rows: Iterable[Dict[str, Any]], keys: List[str]):
    result = {}
    for row in rows:
        key = tuple(row.get(k, "") for k in keys)
        result.setdefault(key, []).append(row)
    return result
