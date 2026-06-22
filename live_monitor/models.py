from __future__ import annotations

from dataclasses import dataclass, asdict
from typing import Any, Dict


@dataclass
class LivePacketEvent:
    timestamp: float
    protocol: str
    src_ip: str
    dst_ip: str
    src_port: int | None
    dst_port: int | None
    length: int
    dns_query: str = ""
    http_host: str = ""
    http_user_agent: str = ""
    tls_sni: str = ""
    tcp_flags_syn: bool = False
    tcp_flags_ack: bool = False
    direction: str = "unknown"
    capture_interface: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @property
    def destination_identity(self) -> str:
        if self.dns_query:
            return self.dns_query
        if self.tls_sni:
            return self.tls_sni
        if self.http_host:
            return self.http_host
        return self.dst_ip
