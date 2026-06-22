from __future__ import annotations

import hashlib
import time
from collections import defaultdict, deque
from typing import Deque, Dict, Iterable, Set, Tuple

from detection_engine.models import Alert, now_iso
from detection_engine.scoring.risk_score import severity
from live_monitor.network_utils import derive_gateway_candidates, is_private_ip, is_special_noise_ip
from host_telemetry.firewall_log import WindowsFirewallEvent

ADMIN_PORTS = {22, 135, 139, 445, 2179, 3389, 5985, 5986, 8501}
COMMON_ALLOW_PORTS = {53, 80, 123, 443, 853, 5353, 1900, 5355, 67, 68}


def stable_alert_id(prefix: str, key: str) -> str:
    digest = hashlib.sha1(key.encode("utf-8")).hexdigest()[:10].upper()
    return f"{prefix}-{digest}"


def priority_for(score: int) -> str:
    if score >= 90:
        return "P1"
    if score >= 75:
        return "P2"
    if score >= 55:
        return "P3"
    return "P4"


class WindowsFirewallDetector:
    """Detect host-targeted scans from Windows Firewall logs.

    This solves the common VM-to-host visibility problem: Npcap may show only ARP
    or partial traffic when Kali runs on the same laptop, but Windows Firewall can
    still log blocked/allowed connection attempts against the Windows host.
    """

    def __init__(
        self,
        local_ips: Iterable[str],
        trusted_ips: Iterable[str] | None = None,
        window_seconds: int = 120,
        cooldown_seconds: int = 120,
        min_portscan_ports: int = 5,
        min_blocked_packets: int = 20,
    ) -> None:
        self.local_ips = set(local_ips)
        self.trusted_ips = set(trusted_ips or set()) | derive_gateway_candidates(self.local_ips)
        self.window_seconds = window_seconds
        self.cooldown_seconds = cooldown_seconds
        self.min_portscan_ports = min_portscan_ports
        self.min_blocked_packets = min_blocked_packets
        self.events: Deque[WindowsFirewallEvent] = deque()
        self.emitted_at: Dict[str, float] = {}

    def process(self, event: WindowsFirewallEvent) -> list[Alert]:
        now = event.timestamp or time.time()
        self.events.append(event)
        self._trim(now)
        if self._is_noise(event):
            return []
        alerts: list[Alert] = []
        scan = self._detect_firewall_port_scan(now)
        if scan and self._allowed(scan.alert_id, now):
            alerts.append(scan)
        return alerts

    def _trim(self, now: float) -> None:
        cutoff = now - self.window_seconds
        while self.events and self.events[0].timestamp < cutoff:
            self.events.popleft()

    def _allowed(self, alert_id: str, now: float) -> bool:
        last = self.emitted_at.get(alert_id)
        if last is not None and now - last < self.cooldown_seconds:
            return False
        self.emitted_at[alert_id] = now
        return True

    def _is_noise(self, e: WindowsFirewallEvent) -> bool:
        if e.src_ip in self.trusted_ips or e.dst_ip in self.trusted_ips:
            return True
        if is_special_noise_ip(e.src_ip) or is_special_noise_ip(e.dst_ip):
            return True
        if e.dst_port in COMMON_ALLOW_PORTS and e.action != "DROP":
            return True
        if e.protocol not in {"TCP", "UDP"}:
            return True
        return False

    def _detect_firewall_port_scan(self, now: float) -> Alert | None:
        cutoff = now - self.window_seconds
        groups: Dict[Tuple[str, str], Set[int]] = defaultdict(set)
        counts: Dict[Tuple[str, str], int] = defaultdict(int)
        drops: Dict[Tuple[str, str], int] = defaultdict(int)
        allows: Dict[Tuple[str, str], int] = defaultdict(int)
        admin_hits: Dict[Tuple[str, str], Set[int]] = defaultdict(set)
        protocols: Dict[Tuple[str, str], Set[str]] = defaultdict(set)

        for e in self.events:
            if e.timestamp < cutoff or not e.dst_port:
                continue
            if self._is_noise(e):
                continue
            # Focus on traffic toward the monitored Windows host or private LAN peers.
            target_is_local = e.dst_ip in self.local_ips
            private_lan_target = is_private_ip(e.src_ip) and is_private_ip(e.dst_ip)
            if not (target_is_local or private_lan_target):
                continue
            key = (e.src_ip, e.dst_ip)
            groups[key].add(e.dst_port)
            counts[key] += 1
            protocols[key].add(e.protocol)
            if e.action == "DROP":
                drops[key] += 1
            elif e.action == "ALLOW":
                allows[key] += 1
            if e.dst_port in ADMIN_PORTS:
                admin_hits[key].add(e.dst_port)

        for (src, dst), ports in groups.items():
            unique_ports = len(ports)
            total = counts[(src, dst)]
            drop_count = drops[(src, dst)]
            allow_count = allows[(src, dst)]
            admin = sorted(admin_hits[(src, dst)])

            scan_detected = (
                unique_ports >= self.min_portscan_ports
                or drop_count >= self.min_blocked_packets
                or (unique_ports >= 3 and bool(admin))
                or (drop_count >= 8 and bool(admin))
            )
            if not scan_detected:
                continue

            score = 65 + min(20, unique_ports // 5) + min(15, drop_count // 20) + len(admin) * 4
            if unique_ports >= 50 or drop_count >= 100:
                score = max(score, 92)
            elif unique_ports >= self.min_portscan_ports or drop_count >= self.min_blocked_packets:
                score = max(score, 80)
            score = min(100, score)
            key = f"winfw-scan:{src}:{dst}:{int(now // 120)}"
            return Alert(
                alert_id=stable_alert_id("WIN-FW-SCAN", key),
                timestamp=now_iso(),
                detection="Windows Firewall Port Scan / Blocked Probe Pattern",
                source_ip=src,
                destination_ip=dst,
                mitre_technique="T1046",
                mitre_tactic="Discovery",
                evidence={
                    "telemetry_source": "Windows Defender Firewall log",
                    "unique_destination_ports": unique_ports,
                    "connection_attempt_count": total,
                    "blocked_or_dropped_count": drop_count,
                    "allowed_count": allow_count,
                    "admin_ports_observed": admin,
                    "sample_ports": sorted(list(ports))[:50],
                    "protocols": sorted(protocols[(src, dst)]),
                    "time_window_seconds": self.window_seconds,
                    "rule_reason": "One source generated many blocked/allowed connection attempts toward the Windows host. This detects scans even when packet capture sees only partial VM-to-host traffic.",
                    "visibility_note": "This is endpoint firewall telemetry, not decrypted packet payload.",
                },
                recommended_action="Confirm whether the source is an approved scanner. If not approved, isolate/investigate the source and review Windows Firewall/Sysmon/Security logs.",
                severity=severity(score),
                risk_score=score,
                confidence="High" if drop_count >= self.min_blocked_packets or unique_ports >= self.min_portscan_ports else "Medium",
                analyst_verdict="Investigate",
                triage_priority=priority_for(score),
                false_positive_considerations="Authorized vulnerability scanners, inventory tools, and IT management software can produce similar firewall patterns. Validate source ownership and scan timing.",
            )
        return None
