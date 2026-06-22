from __future__ import annotations

import hashlib
import json
import math
import statistics
import time
from collections import defaultdict, deque
from pathlib import Path
from typing import Any, Deque, Dict, Iterable, List, Set, Tuple

from detection_engine.models import Alert, now_iso
from detection_engine.scoring.risk_score import severity
from live_monitor.models import LivePacketEvent
from live_monitor.network_utils import (
    derive_gateway_candidates,
    is_private_ip,
    is_special_noise_ip,
)

# Ports that are common in normal desktop traffic. They should not trigger an incident by themselves.
COMMON_OUTBOUND_PORTS = {53, 80, 123, 443, 587, 993, 995, 853}
ADMIN_PORTS = {22, 135, 139, 445, 3389, 5985, 5986}
LOCAL_DISCOVERY_PORTS = {5353, 1900, 5355, 137, 138, 67, 68}
SUSPICIOUS_INTERNAL_PORTS = {4444, 5555, 6666, 7777, 8000, 8080, 8443, 9001}
FILE_TRANSFER_PORTS = {8000, 8080, 3000, 8501}
BENIGN_MULTICAST_DESTS = {"224.0.0.251", "224.0.0.252", "239.255.255.250", "ff02::fb", "ff02::1", "ff02::c"}


def load_threat_intel(path: str | Path | None = None) -> Dict[str, Set[str]]:
    """Load a local allow/block threat-intel file.

    This is configurable detection input, not generated alert data. The detector
    alerts only when live packet metadata matches these domains/IPs.
    """
    default = Path(__file__).resolve().parents[1] / "config" / "threat_intel.json"
    p = Path(path) if path else default
    data: Dict[str, Any] = {}
    if p.exists():
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
        except Exception:
            data = {}
    return {
        "malicious_domains": {str(x).lower().strip(".") for x in data.get("malicious_domains", []) if str(x).strip()},
        "malicious_ips": {str(x).strip() for x in data.get("malicious_ips", []) if str(x).strip()},
        "suspicious_http_headers": {str(x).lower().strip() for x in data.get("suspicious_http_headers", []) if str(x).strip()},
    }


def domain_matches(value: str, domains: Set[str]) -> str | None:
    v = (value or "").lower().strip(".")
    if not v:
        return None
    for d in domains:
        if v == d or v.endswith("." + d):
            return d
    return None


def entropy(value: str) -> float:
    if not value:
        return 0.0
    counts: Dict[str, int] = {}
    for char in value:
        counts[char] = counts.get(char, 0) + 1
    total = len(value)
    return -sum((count / total) * math.log2(count / total) for count in counts.values())


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


class RollingLiveDetector:
    """Stateful production-style real-time detector.

    The detector records all packet metadata as Normal activity, suppresses obvious
    background discovery noise, and promotes behavior to High/Critical only when
    packet patterns resemble real network attacks such as scans, beaconing, DNS
    tunneling, unusual external ports, lateral movement, or large outbound transfer.
    """

    def __init__(
        self,
        local_ips: Iterable[str],
        window_seconds: int = 300,
        cooldown_seconds: int = 300,
        min_portscan_ports: int = 8,
        min_beacon_connections: int = 8,
        exfil_threshold_mb: int = 50,
        trusted_ips: Iterable[str] | None = None,
        suppress_private_discovery: bool = True,
        threat_intel_path: str | Path | None = None,
    ) -> None:
        self.local_ips = set(local_ips)
        self.window_seconds = window_seconds
        self.cooldown_seconds = cooldown_seconds
        self.min_portscan_ports = min_portscan_ports
        self.min_beacon_connections = min_beacon_connections
        self.exfil_threshold_bytes = exfil_threshold_mb * 1024 * 1024
        self.trusted_ips: Set[str] = set(trusted_ips or set()) | derive_gateway_candidates(self.local_ips)
        self.suppress_private_discovery = suppress_private_discovery
        self.threat_intel = load_threat_intel(threat_intel_path)

        self.events: Deque[LivePacketEvent] = deque()
        self.emitted_at: Dict[str, float] = {}

    def process(self, event: LivePacketEvent) -> List[Alert]:
        now = event.timestamp or time.time()
        self.events.append(event)
        self._trim(now)

        # Packet metadata is always written by run_live_monitor.py, but alerting rules
        # suppress common multicast/link-local/router noise.
        if self._is_background_noise(event):
            return []

        alerts: List[Alert] = []
        # Immediate single-event detections are used for high-confidence local tests
        # such as connections to 4444/5555 or downloads from a private HTTP server.
        # These do not rely on long windows, so they are reliable for short-lived
        # attack simulations and real-world one-shot probes.
        for alert in (
            self._detect_direct_admin_or_suspicious_port(event),
            self._detect_private_file_transfer_port(event),
            self._detect_threat_intel_match(event),
            self._detect_dns_anomaly(event),
            self._detect_unusual_external_port(event),
        ):
            if alert and self._allowed(alert.alert_id, now):
                alerts.append(alert)

        for maybe_alert in [
            self._detect_arp_host_discovery(now),
            self._detect_port_scan(now),
            self._detect_unusual_internal_port(now),
            self._detect_beaconing(now),
            self._detect_data_exfiltration(now),
            self._detect_large_inbound_transfer(now),
            self._detect_lateral_movement(now),
        ]:
            if maybe_alert and self._allowed(maybe_alert.alert_id, now):
                alerts.append(maybe_alert)

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

    def _is_trusted_ip(self, ip: str) -> bool:
        return ip in self.trusted_ips

    def _is_background_noise(self, event: LivePacketEvent) -> bool:
        # mDNS, SSDP, LLMNR, IPv6 multicast, link-local discovery, and gateway chatter.
        if event.src_ip in self.trusted_ips or event.dst_ip in self.trusted_ips:
            if event.dst_port in LOCAL_DISCOVERY_PORTS or event.src_port in LOCAL_DISCOVERY_PORTS:
                return True
        if event.dst_ip in BENIGN_MULTICAST_DESTS or event.src_ip in BENIGN_MULTICAST_DESTS:
            return True
        if is_special_noise_ip(event.src_ip) or is_special_noise_ip(event.dst_ip):
            return True
        if event.src_port in LOCAL_DISCOVERY_PORTS or event.dst_port in LOCAL_DISCOVERY_PORTS:
            return True
        return False

    def _connection_start_events(self) -> List[LivePacketEvent]:
        results: List[LivePacketEvent] = []
        for e in self.events:
            if self._is_background_noise(e):
                continue
            if e.protocol in {"TCP", "TLS", "TLSV1.2", "TLSV1.3", "HTTP", "HTTP2"}:
                # TCP SYN without ACK is the closest packet-level representation of a new connection.
                if e.tcp_flags_syn and not e.tcp_flags_ack:
                    results.append(e)
            elif e.protocol in {"UDP", "DNS", "QUIC"}:
                # UDP is connectionless; count packets with destination ports as flow attempts.
                if e.dst_port:
                    results.append(e)
        return results

    def _base_alert_kwargs(self, score: int, confidence: str, verdict: str, fp_note: str) -> Dict[str, Any]:
        return {
            "severity": severity(score),
            "risk_score": score,
            "confidence": confidence,
            "analyst_verdict": verdict,
            "triage_priority": priority_for(score),
            "false_positive_considerations": fp_note,
        }

    def _detect_direct_admin_or_suspicious_port(self, event: LivePacketEvent) -> Alert | None:
        """Reliable detection for short-lived local probes and reverse-shell-style ports.

        This covers cases where a test such as `Test-NetConnection 192.168.4.189
        -Port 4444` opens only a very short TCP connection. Waiting for a rolling
        threshold can miss that behavior, so this rule emits a single High/Critical
        alert when a non-trusted internal host communicates on admin or suspicious
        ports.
        """
        if self._is_background_noise(event):
            return None
        if not (is_private_ip(event.src_ip) and is_private_ip(event.dst_ip)):
            return None
        if self._is_trusted_ip(event.src_ip) or self._is_trusted_ip(event.dst_ip):
            return None

        involved_port = None
        # Connection from Windows/local host to Kali listener, e.g. dst_port 4444.
        if event.dst_port in SUSPICIOUS_INTERNAL_PORTS or event.dst_port in ADMIN_PORTS:
            involved_port = event.dst_port
        # Response from Kali/remote local service back to Windows, e.g. src_port 8000/4444.
        elif event.src_port in SUSPICIOUS_INTERNAL_PORTS or event.src_port in ADMIN_PORTS:
            involved_port = event.src_port
        if involved_port is None:
            return None

        # Avoid marking ordinary web apps as Critical unless they use explicit suspicious ports.
        if involved_port in FILE_TRANSFER_PORTS and event.length < 200:
            return None

        if involved_port in {4444, 5555, 6666, 7777}:
            score = 90
            detection = "Live Reverse-Shell/Suspicious Listener Port"
            technique = "T1105"
            tactic = "Command and Control"
            reason = "Internal communication used a commonly abused listener/reverse-shell port."
        elif involved_port in ADMIN_PORTS:
            score = 86
            detection = "Live Administrative Service Probe"
            technique = "T1046"
            tactic = "Discovery"
            reason = "Internal host communicated with a Windows/admin service port."
        else:
            score = 78
            detection = "Live Suspicious Internal Port Communication"
            technique = "T1021"
            tactic = "Lateral Movement"
            reason = "Internal host communicated on a non-standard service/test port."

        key = f"direct-port:{event.src_ip}:{event.dst_ip}:{involved_port}:{int((event.timestamp or time.time()) // 60)}"
        return Alert(
            alert_id=stable_alert_id("LIVE-DIRECT", key),
            timestamp=now_iso(),
            detection=detection,
            source_ip=event.src_ip,
            destination_ip=event.dst_ip,
            mitre_technique=technique,
            mitre_tactic=tactic,
            evidence={
                "telemetry_source": "TShark/Npcap packet metadata",
                "source_port": event.src_port,
                "destination_port": event.dst_port,
                "involved_port": involved_port,
                "protocol": event.protocol,
                "packet_length": event.length,
                "direction": event.direction,
                "rule_reason": reason,
                "reliability_note": "Single-event local probe detection is enabled so short-lived connections do not get missed by rolling-window thresholds.",
            },
            recommended_action="Verify whether this was an approved test. If not, identify the process and inspect the source host for scanning, shells, or unauthorized services.",
            **self._base_alert_kwargs(
                score,
                "High",
                "Investigate",
                "Developer services can use custom ports; validate source, process, and timing before escalation.",
            ),
        )

    def _detect_threat_intel_match(self, event: LivePacketEvent) -> Alert | None:
        """Alert when live DNS/HTTP/TLS/IP metadata matches local threat intel.

        Ping has no HTTP headers, so ping-based alerts can only use DNS resolution
        and destination IP metadata. HTTP Host/SNI alerts require curl/browser HTTP/TLS
        metadata to be visible.
        """
        malicious_domains = self.threat_intel.get("malicious_domains", set())
        malicious_ips = self.threat_intel.get("malicious_ips", set())
        suspicious_headers = self.threat_intel.get("suspicious_http_headers", set())

        matched_domain = None
        matched_field = None
        for field_name, value in (
            ("dns_query", event.dns_query),
            ("http_host", event.http_host),
            ("tls_sni", event.tls_sni),
        ):
            match = domain_matches(value, malicious_domains)
            if match:
                matched_domain = match
                matched_field = field_name
                break

        matched_ip = None
        if event.src_ip in malicious_ips:
            matched_ip = event.src_ip
        elif event.dst_ip in malicious_ips:
            matched_ip = event.dst_ip

        matched_header = None
        ua = (getattr(event, "http_user_agent", "") or "").lower()
        for marker in suspicious_headers:
            if marker and marker in ua:
                matched_header = marker
                break

        if not (matched_domain or matched_ip or matched_header):
            return None

        score = 92 if matched_ip or matched_domain else 82
        key = f"ti:{event.src_ip}:{event.dst_ip}:{matched_domain or matched_ip or matched_header}:{int((event.timestamp or time.time()) // 120)}"
        return Alert(
            alert_id=stable_alert_id("LIVE-TI", key),
            timestamp=now_iso(),
            detection="Live Threat Intelligence Match",
            source_ip=event.src_ip,
            destination_ip=event.dst_ip,
            mitre_technique="T1071",
            mitre_tactic="Command and Control",
            evidence={
                "telemetry_source": "TShark/Npcap packet metadata",
                "matched_domain": matched_domain,
                "matched_ip": matched_ip,
                "matched_field": matched_field,
                "matched_http_marker": matched_header,
                "dns_query": event.dns_query,
                "http_host": event.http_host,
                "tls_sni": event.tls_sni,
                "destination_port": event.dst_port,
                "protocol": event.protocol,
                "rule_reason": "Live metadata matched a configurable malicious domain/IP/header marker in config/threat_intel.json.",
                "important_note": "ICMP ping has no HTTP headers. Ping alerts come from DNS/IP matching, while HTTP header/host alerts require HTTP/TLS metadata.",
            },
            recommended_action="Block or investigate the destination, identify the process/user that generated the traffic, and validate against external threat intelligence.",
            **self._base_alert_kwargs(
                score,
                "High",
                "Investigate",
                "Threat-intel matches depend on list quality; verify the domain/IP before escalation.",
            ),
        )

    def _detect_private_file_transfer_port(self, event: LivePacketEvent) -> Alert | None:
        """Detect private HTTP/file-transfer traffic even when the transfer is short.

        A 100MB download from Kali's `python3 -m http.server 8000` should create a
        visible incident quickly. The volume rule still runs, but this catches the
        first meaningful packets on common ad-hoc file-transfer ports.
        """
        if self._is_background_noise(event):
            return None
        if not (is_private_ip(event.src_ip) and is_private_ip(event.dst_ip)):
            return None
        if self._is_trusted_ip(event.src_ip) or self._is_trusted_ip(event.dst_ip):
            return None
        transfer_port = None
        if event.src_port in FILE_TRANSFER_PORTS:
            transfer_port = event.src_port
        elif event.dst_port in FILE_TRANSFER_PORTS:
            transfer_port = event.dst_port
        if transfer_port is None:
            return None
        if event.length < 500:
            return None

        # Inbound/private file transfer to the Windows host is more important than a small request packet.
        local_is_destination = event.dst_ip in self.local_ips
        score = 86 if local_is_destination else 76
        key = f"file-port:{event.src_ip}:{event.dst_ip}:{transfer_port}:{int((event.timestamp or time.time()) // 120)}"
        return Alert(
            alert_id=stable_alert_id("LIVE-FILEPORT", key),
            timestamp=now_iso(),
            detection="Live File Transfer / Ad-hoc HTTP Service",
            source_ip=event.src_ip,
            destination_ip=event.dst_ip,
            mitre_technique="T1105",
            mitre_tactic="Command and Control",
            evidence={
                "telemetry_source": "TShark/Npcap packet metadata",
                "transfer_port": transfer_port,
                "source_port": event.src_port,
                "destination_port": event.dst_port,
                "packet_length": event.length,
                "direction": event.direction,
                "rule_reason": "Private host used an ad-hoc service/file-transfer port with meaningful payload-sized packets.",
                "content_note": "File names and contents are not decrypted; this is metadata and port/volume based.",
            },
            recommended_action="Validate whether the file transfer was expected. Check the source host, downloaded file, hash, and user action.",
            **self._base_alert_kwargs(
                score,
                "High",
                "Investigate",
                "Developer web servers and lab transfers can be legitimate; verify business/user intent.",
            ),
        )

    def _detect_dns_anomaly(self, event: LivePacketEvent) -> Alert | None:
        query = event.dns_query.strip(".")
        if not query:
            return None

        query_length = len(query)
        labels = [p for p in query.split(".") if p]
        subdomain_depth = max(0, len(labels) - 2)
        first_label = labels[0] if labels else query
        ent = entropy(first_label)

        # Production thresholds: long/high-entropy DNS labels can indicate tunneling.
        # Do NOT alert on subdomain depth alone; Microsoft/CDN telemetry often has
        # 4-6 labels but low entropy and short total length.
        suspicious = query_length >= 60 or (ent >= 4.0 and len(first_label) >= 28) or (subdomain_depth >= 7 and query_length >= 50)
        if not suspicious:
            return None

        score = min(100, 45 + query_length // 3 + int(ent * 8) + max(0, subdomain_depth - 2) * 4)
        key = f"dns:{event.src_ip}:{query[:80]}"
        return Alert(
            alert_id=stable_alert_id("LIVE-DNS", key),
            timestamp=now_iso(),
            detection="Live Suspicious DNS / Possible DNS Tunneling",
            source_ip=event.src_ip,
            destination_ip=event.dst_ip,
            mitre_technique="T1071.004",
            mitre_tactic="Command and Control",
            evidence={
                "dns_query": query,
                "query_length": query_length,
                "subdomain_depth": subdomain_depth,
                "first_label_entropy": round(ent, 2),
                "rule_reason": "Long, deep, or high-entropy DNS query observed in live traffic.",
                "tuning_note": "Ordinary short DNS/CDN queries are ignored to reduce false positives.",
            },
            recommended_action="Review the domain, parent process, resolver path, and whether similar queries repeat periodically.",
            **self._base_alert_kwargs(
                score,
                "Medium",
                "Needs Review",
                "CDN, telemetry, and tracking domains can be long; validate repetition and process context before escalation.",
            ),
        )

    def _detect_unusual_external_port(self, event: LivePacketEvent) -> Alert | None:
        if event.direction not in {"outbound", "outbound_private"}:
            return None
        if not event.dst_port:
            return None
        if is_private_ip(event.dst_ip) or self._is_trusted_ip(event.dst_ip) or is_special_noise_ip(event.dst_ip):
            return None
        if event.dst_port in COMMON_OUTBOUND_PORTS or event.dst_port in LOCAL_DISCOVERY_PORTS:
            return None
        if event.length < 80:
            # Ignore tiny ACK/keepalive noise.
            return None

        # Make one-off unusual ports medium, admin ports high, and repeated behavior handled by beaconing/volume rules.
        score = 60 if event.dst_port not in ADMIN_PORTS else 78
        key = f"unusual-port:{event.src_ip}:{event.dst_ip}:{event.dst_port}"
        return Alert(
            alert_id=stable_alert_id("LIVE-PORT", key),
            timestamp=now_iso(),
            detection="Live Unusual External Connection Port",
            source_ip=event.src_ip,
            destination_ip=event.dst_ip,
            mitre_technique="T1071",
            mitre_tactic="Command and Control",
            evidence={
                "destination_port": event.dst_port,
                "protocol": event.protocol,
                "direction": event.direction,
                "packet_length": event.length,
                "rule_reason": "Outbound connection to a non-common external port.",
                "suppressed_noise": "Private, multicast, link-local, discovery ports, and common web/DNS/NTP ports are suppressed.",
            },
            recommended_action="Validate destination IP/port against known apps. Check process ownership using netstat/Get-NetTCPConnection and browser/app activity.",
            **self._base_alert_kwargs(
                score,
                "Medium",
                "Needs Review",
                "Some applications use non-standard ports; confirm whether the destination belongs to expected software.",
            ),
        )

    def _detect_arp_host_discovery(self, now: float) -> Alert | None:
        """Detect local host discovery from ARP telemetry.

        When Kali/VirtualBox scans the Windows host from the same laptop, Npcap can
        sometimes show ARP clearly while TCP probes are hidden by the local virtual
        bridge path. This rule does not pretend ARP is a full port scan; it records
        attacker host discovery that commonly appears immediately before Nmap scans.
        """
        cutoff = now - 120
        groups: Dict[Tuple[str, str], int] = defaultdict(int)
        for e in self.events:
            if e.timestamp < cutoff:
                continue
            if e.protocol != "ARP":
                continue
            if not e.src_ip or not e.dst_ip:
                continue
            if e.src_ip in self.trusted_ips or e.dst_ip in self.trusted_ips:
                continue
            if e.dst_ip not in self.local_ips:
                continue
            groups[(e.src_ip, e.dst_ip)] += 1

        for (src, dst), count in groups.items():
            # One ARP query from a non-trusted local host to the monitored Windows host
            # is useful evidence when testing VM-to-host scans, where TCP probes may
            # be hidden by the local virtual bridge.
            if count < 1:
                continue
            score = 72 if count < 3 else 82
            key = f"arp-discovery:{src}:{dst}:{int(now // 180)}"
            return Alert(
                alert_id=stable_alert_id("LIVE-ARP", key),
                timestamp=now_iso(),
                detection="Live ARP Host Discovery / Scan Preparation",
                source_ip=src,
                destination_ip=dst,
                mitre_technique="T1046",
                mitre_tactic="Discovery",
                evidence={
                    "telemetry_source": "TShark/Npcap ARP metadata",
                    "arp_query_count": count,
                    "time_window_seconds": 120,
                    "rule_reason": "A non-trusted local host repeatedly resolved the Windows host MAC address. This commonly precedes local Nmap/service scans.",
                    "visibility_note": "This is host-discovery evidence; check packet/firewall telemetry for follow-on TCP probes.",
                },
                recommended_action="Verify whether the source is your Kali/test scanner or an approved inventory scanner. Review follow-on TCP events and firewall logs.",
                **self._base_alert_kwargs(
                    score,
                    "Medium",
                    "Investigate",
                    "ARP is normal on local networks; escalate only when correlated with scans or unexpected source hosts.",
                ),
            )
        return None

    def _detect_port_scan(self, now: float) -> Alert | None:
        """Detect vertical/service scans without misclassifying CDN/browser traffic.

        Earlier builds counted ordinary inbound TLS packets to random client ephemeral
        ports as scans. This version only counts true TCP connection starts (SYN
        without ACK) or response-side evidence from local service/admin ports.
        """
        cutoff = now - 90
        groups: Dict[Tuple[str, str], Set[int]] = defaultdict(set)
        packet_counts: Dict[Tuple[str, str], int] = defaultdict(int)
        syn_counts: Dict[Tuple[str, str], int] = defaultdict(int)
        admin_port_hits: Dict[Tuple[str, str], Set[int]] = defaultdict(set)
        response_side_hits: Dict[Tuple[str, str], Set[int]] = defaultdict(set)

        for e in self.events:
            if e.timestamp < cutoff:
                continue
            if self._is_background_noise(e):
                continue
            if self._is_trusted_ip(e.src_ip) or self._is_trusted_ip(e.dst_ip):
                continue
            if is_special_noise_ip(e.src_ip) or is_special_noise_ip(e.dst_ip):
                continue
            if e.protocol not in {"TCP", "TLS", "TLSV1.2", "TLSV1.3", "HTTP", "HTTP2"}:
                continue

            # Direct scan/probe evidence: remote host sends TCP SYN to the monitored host.
            if e.dst_ip in self.local_ips and e.dst_port and e.tcp_flags_syn and not e.tcp_flags_ack:
                key = (e.src_ip, e.dst_ip)
                groups[key].add(e.dst_port)
                packet_counts[key] += 1
                syn_counts[key] += 1
                if e.dst_port in ADMIN_PORTS or e.dst_port in SUSPICIOUS_INTERNAL_PORTS:
                    admin_port_hits[key].add(e.dst_port)

            # Response-side evidence: local service/admin ports answer a remote peer.
            # This is useful for Windows host scans where Npcap sees replies better
            # than the entire probe stream.
            if e.src_ip in self.local_ips and e.src_port in (ADMIN_PORTS | SUSPICIOUS_INTERNAL_PORTS) and e.dst_ip not in self.local_ips:
                key = (e.dst_ip, e.src_ip)  # scanner -> target
                if not self._is_trusted_ip(e.dst_ip) and not is_special_noise_ip(e.dst_ip):
                    groups[key].add(e.src_port)
                    packet_counts[key] += 1
                    response_side_hits[key].add(e.src_port)
                    if e.src_port in ADMIN_PORTS:
                        admin_port_hits[key].add(e.src_port)

        for (src, dst), ports in groups.items():
            unique_ports = len(ports)
            attempts = packet_counts[(src, dst)]
            syns = syn_counts[(src, dst)]
            admin_hits = sorted(admin_port_hits[(src, dst)])
            response_hits = sorted(response_side_hits[(src, dst)])
            src_is_private = is_private_ip(src)

            scan_detected = (
                unique_ports >= self.min_portscan_ports
                or syns >= max(10, self.min_portscan_ports * 2)
                or (src_is_private and unique_ports >= 2 and attempts >= 2 and (admin_hits or response_hits))
                or (src_is_private and unique_ports >= 1 and admin_hits)
                or (src_is_private and unique_ports >= 1 and response_hits and attempts >= 1)
            )
            if not scan_detected:
                continue

            score = 64 + unique_ports * 5 + min(22, syns // 2) + len(admin_hits) * 5
            if unique_ports >= 5 or syns >= 20:
                score = max(score, 90)
            elif src_is_private and admin_hits:
                score = max(score, 86)
            elif unique_ports >= 2 and src_is_private:
                score = max(score, 78)
            score = min(100, score)
            key = f"portscan:{src}:{dst}:{int(now // 120)}"
            return Alert(
                alert_id=stable_alert_id("LIVE-SCAN", key),
                timestamp=now_iso(),
                detection="Live Port Scan / Service Discovery",
                source_ip=src,
                destination_ip=dst,
                mitre_technique="T1046",
                mitre_tactic="Discovery",
                evidence={
                    "telemetry_source": "TShark/Npcap packet metadata",
                    "unique_destination_ports": unique_ports,
                    "packet_count": attempts,
                    "syn_count": syns,
                    "admin_ports_observed": admin_hits,
                    "response_side_service_ports": response_hits,
                    "sample_ports": sorted(list(ports))[:50],
                    "time_window_seconds": 90,
                    "rule_reason": "One source contacted multiple service ports or generated repeated TCP SYN attempts toward the monitored host.",
                    "false_positive_fix": "Inbound TLS/QUIC browser return traffic to random client ports is no longer counted as a port scan.",
                },
                recommended_action="Confirm whether the source is an approved scanner. If not, isolate/investigate the source host and review firewall/endpoint logs.",
                **self._base_alert_kwargs(
                    score,
                    "High" if score >= 75 else "Medium",
                    "Investigate",
                    "Authorized vulnerability scanners and IT inventory tools can look similar; validate source ownership and scan window.",
                ),
            )
        return None

    def _detect_unusual_internal_port(self, now: float) -> Alert | None:
        cutoff = now - 90
        groups: Dict[Tuple[str, str, int], int] = defaultdict(int)
        for e in self.events:
            if e.timestamp < cutoff or not e.dst_port:
                continue
            if self._is_background_noise(e):
                continue
            if self._is_trusted_ip(e.src_ip) or self._is_trusted_ip(e.dst_ip):
                continue
            if not (is_private_ip(e.src_ip) and is_private_ip(e.dst_ip)):
                continue
            if e.dst_port not in SUSPICIOUS_INTERNAL_PORTS and e.dst_port not in ADMIN_PORTS:
                continue
            if e.length < 40:
                continue
            groups[(e.src_ip, e.dst_ip, e.dst_port)] += 1

        for (src, dst, port), count in groups.items():
            if count < 2 and port not in {4444, 5555, 6666, 7777}:
                continue
            score = 72 if port in ADMIN_PORTS else 76
            if port in {4444, 5555, 6666, 7777}:
                score = 86
            key = f"internal-port:{src}:{dst}:{port}:{int(now // 180)}"
            return Alert(
                alert_id=stable_alert_id("LIVE-INTPORT", key),
                timestamp=now_iso(),
                detection="Live Suspicious Internal Port Communication",
                source_ip=src,
                destination_ip=dst,
                mitre_technique="T1021",
                mitre_tactic="Lateral Movement",
                evidence={
                    "destination_port": port,
                    "connection_packet_count": count,
                    "time_window_seconds": 90,
                    "rule_reason": "Internal host communicated on an admin or suspicious non-standard port.",
                },
                recommended_action="Verify whether the port is expected. For ports such as 4444/5555, check for shells, listeners, or unauthorized tools.",
                **self._base_alert_kwargs(
                    score,
                    "High",
                    "Investigate",
                    "Developer servers and test tools can use high ports; validate the process and user context.",
                ),
            )
        return None

    def _detect_beaconing(self, now: float) -> Alert | None:
        groups: Dict[Tuple[str, str, int | None], List[float]] = defaultdict(list)
        for e in self._connection_start_events():
            if e.direction not in {"outbound", "outbound_private"}:
                continue
            if is_private_ip(e.dst_ip) or is_special_noise_ip(e.dst_ip) or self._is_trusted_ip(e.dst_ip):
                continue
            if e.dst_port in LOCAL_DISCOVERY_PORTS:
                continue
            groups[(e.src_ip, e.dst_ip, e.dst_port)].append(e.timestamp)

        for (src, dst, dport), timestamps in groups.items():
            timestamps = sorted(timestamps)
            if len(timestamps) < self.min_beacon_connections:
                continue
            intervals = [b - a for a, b in zip(timestamps, timestamps[1:])]
            if not intervals:
                continue
            avg = statistics.mean(intervals)
            stdev = statistics.pstdev(intervals) if len(intervals) > 1 else 0.0
            # Avoid browser burst noise: need stable spacing and at least 8 connections.
            if 10 <= avg <= 300 and stdev <= max(2.0, avg * 0.20):
                score = min(100, 55 + len(timestamps) * 3 + max(0, int(25 - stdev)))
                key = f"beacon:{src}:{dst}:{dport}:{int(now // 300)}"
                return Alert(
                    alert_id=stable_alert_id("LIVE-BEACON", key),
                    timestamp=now_iso(),
                    detection="Live Beaconing / C2-Like Traffic",
                    source_ip=src,
                    destination_ip=dst,
                    mitre_technique="T1071",
                    mitre_tactic="Command and Control",
                    evidence={
                        "destination_port": dport,
                        "connection_count": len(timestamps),
                        "average_interval_seconds": round(avg, 2),
                        "interval_stdev_seconds": round(stdev, 2),
                        "time_window_seconds": self.window_seconds,
                        "rule_reason": "Repeated outbound connections to the same destination at a stable interval.",
                    },
                    recommended_action="Identify the process owning the connection and validate destination reputation. Check whether traffic continues after closing browsers/apps.",
                    **self._base_alert_kwargs(
                        score,
                        "High",
                        "Investigate",
                        "Some update agents and cloud sync tools beacon normally; verify process and business justification.",
                    ),
                )
        return None

    def _detect_data_exfiltration(self, now: float) -> Alert | None:
        cutoff = now - 120
        groups: Dict[Tuple[str, str], int] = defaultdict(int)
        packet_counts: Dict[Tuple[str, str], int] = defaultdict(int)
        for e in self.events:
            if e.timestamp < cutoff:
                continue
            if self._is_background_noise(e):
                continue
            if e.direction not in {"outbound", "outbound_private"}:
                continue
            if is_private_ip(e.dst_ip) or is_special_noise_ip(e.dst_ip) or self._is_trusted_ip(e.dst_ip):
                continue
            key = (e.src_ip, e.dst_ip)
            groups[key] += max(0, e.length)
            packet_counts[key] += 1

        for (src, dst), bytes_out in groups.items():
            if bytes_out >= self.exfil_threshold_bytes:
                mb = bytes_out / (1024 * 1024)
                score = min(100, 65 + int(mb))
                key = f"exfil:{src}:{dst}:{int(now // 240)}"
                return Alert(
                    alert_id=stable_alert_id("LIVE-EXFIL", key),
                    timestamp=now_iso(),
                    detection="Live Suspicious Outbound Data Transfer",
                    source_ip=src,
                    destination_ip=dst,
                    mitre_technique="T1041",
                    mitre_tactic="Exfiltration",
                    evidence={
                        "bytes_out_estimate": bytes_out,
                        "megabytes_out_estimate": round(mb, 2),
                        "packet_count": packet_counts[(src, dst)],
                        "time_window_seconds": 120,
                        "rule_reason": "Large outbound volume to an external destination in a short time window.",
                    },
                    recommended_action="Validate whether the transfer is expected. Check process, destination, file movement, and user activity before closing.",
                    **self._base_alert_kwargs(
                        score,
                        "High",
                        "Investigate",
                        "Cloud backup, Git operations, video calls, or large downloads/uploads can produce high volume; validate context.",
                    ),
                )
        return None

    def _detect_large_inbound_transfer(self, now: float) -> Alert | None:
        """Detect large file/download transfers into the monitored host.

        This covers tests like downloading a 100MB file from Kali over python3 -m
        http.server. HTTPS payload is not decrypted; detection is based on volume,
        source/destination, port, and time window.
        """
        cutoff = now - 180
        groups: Dict[Tuple[str, str, int | None], int] = defaultdict(int)
        packet_counts: Dict[Tuple[str, str, int | None], int] = defaultdict(int)
        for e in self.events:
            if e.timestamp < cutoff:
                continue
            if self._is_background_noise(e):
                continue
            if e.direction not in {"inbound", "inbound_private"}:
                continue
            if e.dst_ip not in self.local_ips:
                continue
            if self._is_trusted_ip(e.src_ip) or is_special_noise_ip(e.src_ip):
                continue
            key = (e.src_ip, e.dst_ip, e.src_port)
            groups[key] += max(0, e.length)
            packet_counts[key] += 1

        for (src, dst, sport), bytes_in in groups.items():
            mb = bytes_in / (1024 * 1024)
            # Practical demo threshold: 5MB+ is High and 25MB+ is Critical.
            # This reliably detects a 100MB Kali HTTP-server download without
            # waiting for every packet to be captured by Npcap.
            if mb < 5:
                continue
            score = 78 + min(20, int(mb // 3))
            if mb >= 25:
                score = max(score, 88)
            score = min(100, score)
            key = f"inbound-transfer:{src}:{dst}:{sport}:{int(now // 240)}"
            return Alert(
                alert_id=stable_alert_id("LIVE-INTRANSFER", key),
                timestamp=now_iso(),
                detection="Live Large Inbound File Transfer",
                source_ip=src,
                destination_ip=dst,
                mitre_technique="T1105",
                mitre_tactic="Command and Control",
                evidence={
                    "telemetry_source": "TShark/Npcap packet metadata",
                    "source_port": sport,
                    "bytes_in_estimate": bytes_in,
                    "megabytes_in_estimate": round(mb, 2),
                    "packet_count": packet_counts[(src, dst, sport)],
                    "time_window_seconds": 180,
                    "rule_reason": "Large inbound transfer to the monitored host observed in a short window.",
                    "content_note": "File contents and filenames are not decrypted; this is metadata/volume-based detection.",
                },
                recommended_action="Confirm whether the file transfer was expected. Validate source host, port, downloaded file, hash, and user action.",
                **self._base_alert_kwargs(
                    score,
                    "High",
                    "Investigate",
                    "Legitimate downloads, updates, and lab file transfers can trigger this; verify user intent and source trust.",
                ),
            )
        return None

    def _detect_lateral_movement(self, now: float) -> Alert | None:
        cutoff = now - 120
        groups: Dict[str, Dict[str, set[int]]] = defaultdict(lambda: defaultdict(set))
        for e in self._connection_start_events():
            if e.timestamp < cutoff or not e.dst_port:
                continue
            if self._is_trusted_ip(e.src_ip) or self._is_trusted_ip(e.dst_ip):
                continue
            if e.dst_port not in ADMIN_PORTS:
                continue
            if not (is_private_ip(e.src_ip) and is_private_ip(e.dst_ip)):
                continue
            groups[e.src_ip][e.dst_ip].add(e.dst_port)

        for src, dests in groups.items():
            unique_destinations = len(dests)
            touched_ports = sorted({p for ports in dests.values() for p in ports})
            if unique_destinations >= 3 or len(touched_ports) >= 3:
                score = min(100, 55 + unique_destinations * 10 + len(touched_ports) * 8)
                key = f"lateral:{src}:{int(now // 240)}"
                return Alert(
                    alert_id=stable_alert_id("LIVE-LATERAL", key),
                    timestamp=now_iso(),
                    detection="Live Lateral Movement-Like Internal Communication",
                    source_ip=src,
                    destination_ip=", ".join(sorted(dests.keys())[:5]),
                    mitre_technique="T1021",
                    mitre_tactic="Lateral Movement",
                    evidence={
                        "unique_internal_destinations": unique_destinations,
                        "admin_ports_observed": touched_ports,
                        "time_window_seconds": 120,
                        "rule_reason": "Internal host contacted multiple peers or admin ports in a short window.",
                    },
                    recommended_action="Confirm whether this host is an admin/jump box. If not, investigate remote access attempts and endpoint logs.",
                    **self._base_alert_kwargs(
                        score,
                        "High",
                        "Investigate",
                        "Patch scanners, inventory tools, and admin scripts can look similar; verify authorization.",
                    ),
                )
        return None
