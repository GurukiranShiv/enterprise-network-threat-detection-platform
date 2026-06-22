from __future__ import annotations

import csv
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Iterator, List, Optional

DEFAULT_FIREWALL_LOG = Path(r"C:\Windows\System32\LogFiles\Firewall\pfirewall.log")


@dataclass
class WindowsFirewallEvent:
    timestamp: float
    action: str
    protocol: str
    src_ip: str
    dst_ip: str
    src_port: int | None
    dst_port: int | None
    size: int
    tcp_flags: str = ""
    tcp_syn: bool = False
    tcp_ack: bool = False
    direction: str = "unknown"
    path: str = ""
    telemetry_source: str = "windows_firewall"

    def to_dict(self) -> Dict[str, object]:
        return asdict(self)


def _to_int(value: str | None) -> int | None:
    if value in (None, "", "-"):
        return None
    try:
        return int(str(value))
    except Exception:
        return None


def _to_float(value: str | None) -> float:
    n = _to_int(value)
    return float(n or 0)


def _parse_timestamp(date_value: str, time_value: str) -> float:
    # Windows Firewall log uses separate date/time fields. Treat as local time if no
    # timezone is provided; exact UTC/local does not affect rolling-window detection.
    try:
        dt = datetime.strptime(f"{date_value} {time_value}", "%Y-%m-%d %H:%M:%S")
        return dt.replace(tzinfo=timezone.utc).timestamp()
    except Exception:
        return time.time()


def _infer_direction(src_ip: str, dst_ip: str, local_ips: set[str]) -> str:
    if src_ip in local_ips and dst_ip not in local_ips:
        return "outbound"
    if dst_ip in local_ips and src_ip not in local_ips:
        return "inbound"
    if src_ip in local_ips and dst_ip in local_ips:
        return "local"
    return "unknown"


def parse_firewall_log_line(line: str, fields: List[str], local_ips: set[str]) -> WindowsFirewallEvent | None:
    if not line or line.startswith("#") or not fields:
        return None
    # The firewall log is space separated and path/info fields can be '-'. csv with
    # delimiter=' ' handles repeated whitespace poorly, so split is intentional here.
    parts = line.strip().split()
    if len(parts) < 8:
        return None
    row = {name: parts[i] if i < len(parts) else "" for i, name in enumerate(fields)}

    action = row.get("action", "").upper()
    protocol = row.get("protocol", "").upper()
    src_ip = row.get("src-ip", "")
    dst_ip = row.get("dst-ip", "")
    if not src_ip or not dst_ip or src_ip == "-" or dst_ip == "-":
        return None

    src_port = _to_int(row.get("src-port"))
    dst_port = _to_int(row.get("dst-port"))
    tcp_flags = row.get("tcpflags", "") or ""
    tcp_syn = "S" in tcp_flags.upper()
    tcp_ack = "A" in tcp_flags.upper()

    return WindowsFirewallEvent(
        timestamp=_parse_timestamp(row.get("date", ""), row.get("time", "")),
        action=action,
        protocol=protocol,
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        size=_to_int(row.get("size")) or 0,
        tcp_flags=tcp_flags,
        tcp_syn=tcp_syn,
        tcp_ack=tcp_ack,
        direction=_infer_direction(src_ip, dst_ip, local_ips),
        path=row.get("path", "") or "",
    )


def read_existing_firewall_events(path: Path, local_ips: set[str], max_lines: int = 5000) -> list[WindowsFirewallEvent]:
    if not path.exists():
        return []
    try:
        lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()[-max_lines:]
    except Exception:
        return []
    fields: list[str] = []
    events: list[WindowsFirewallEvent] = []
    for line in lines:
        if line.startswith("#Fields:"):
            fields = line.replace("#Fields:", "", 1).strip().split()
            continue
        ev = parse_firewall_log_line(line, fields, local_ips)
        if ev:
            events.append(ev)
    return events


def stream_firewall_events(
    path: str | Path = DEFAULT_FIREWALL_LOG,
    local_ips: set[str] | None = None,
    read_existing: bool = False,
    poll_seconds: float = 1.0,
) -> Iterator[WindowsFirewallEvent]:
    """Tail Windows Defender Firewall log and yield parsed events.

    The monitor starts at the end of the file by default so old historical firewall
    entries do not become new incidents. Use read_existing=True for testing.
    """
    local = local_ips or set()
    p = Path(path)
    fields: list[str] = []

    while not p.exists():
        time.sleep(poll_seconds)

    with p.open("r", encoding="utf-8", errors="ignore") as f:
        if not read_existing:
            f.seek(0, 2)
        else:
            f.seek(0)
        while True:
            line = f.readline()
            if not line:
                time.sleep(poll_seconds)
                continue
            line = line.strip()
            if line.startswith("#Fields:"):
                fields = line.replace("#Fields:", "", 1).strip().split()
                continue
            if not fields:
                continue
            ev = parse_firewall_log_line(line, fields, local)
            if ev:
                yield ev
