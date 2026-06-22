from __future__ import annotations

import argparse
import queue
import shutil
import signal
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from detection_engine.elastic_writer import send_alerts
from host_telemetry.firewall_log import DEFAULT_FIREWALL_LOG, WindowsFirewallEvent, stream_firewall_events
from host_telemetry.windows_firewall_detector import WindowsFirewallDetector
from live_monitor.live_detector import RollingLiveDetector
from live_monitor.network_utils import get_local_ips
from live_monitor.tshark_interface import resolve_interfaces, stream_events
from live_monitor.writers import append_jsonl, atomic_write_json, read_json_list, write_alerts

STOP = False


def _handle_stop(signum, frame):  # type: ignore[no-untyped-def]
    global STOP
    STOP = True
    print("\nStopping hybrid NDR monitor...", flush=True)


def _packet_worker(
    out_q: "queue.Queue[tuple[str, Any]]",
    interfaces: list[str],
    local_ips: set[str],
    capture_filter: str | None,
) -> None:
    try:
        for event in stream_events(interfaces, local_ips, capture_filter):
            if STOP:
                break
            out_q.put(("packet", event))
    except Exception as exc:
        out_q.put(("error", f"TShark worker error: {exc}"))


def _firewall_worker(
    out_q: "queue.Queue[tuple[str, Any]]",
    log_path: str,
    local_ips: set[str],
    read_existing: bool,
) -> None:
    try:
        for event in stream_firewall_events(log_path, local_ips, read_existing=read_existing):
            if STOP:
                break
            out_q.put(("firewall", event))
    except Exception as exc:
        out_q.put(("error", f"Windows Firewall log worker error: {exc}"))


def _firewall_event_to_live_row(event: WindowsFirewallEvent) -> Dict[str, Any]:
    """Normalize firewall telemetry to the same JSONL shape used by packet metadata."""
    return {
        "timestamp": event.timestamp,
        "protocol": event.protocol,
        "src_ip": event.src_ip,
        "dst_ip": event.dst_ip,
        "src_port": event.src_port,
        "dst_port": event.dst_port,
        "length": event.size,
        "dns_query": "",
        "http_host": "",
        "tls_sni": "",
        "tcp_flags_syn": event.tcp_syn,
        "tcp_flags_ack": event.tcp_ack,
        "direction": event.direction,
        "capture_interface": "windows_firewall",
        "telemetry_source": "windows_firewall",
        "firewall_action": event.action,
        "tcp_flags": event.tcp_flags,
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Hybrid live NDR monitor: TShark/Npcap packets + Windows Firewall host telemetry."
    )
    parser.add_argument("--interface", default="all", help='TShark interface number/name, or "all". Default: all')
    parser.add_argument("--interfaces", default=None, help='Comma-separated TShark interfaces, e.g. "6,9,11"')
    parser.add_argument("--include-loopback", action="store_true", help="Include loopback when --interface all is used")
    parser.add_argument("--capture-filter", default=None, help='Optional BPF filter for TShark, e.g. "ip and not broadcast"')
    parser.add_argument("--no-packets", action="store_true", help="Disable TShark packet capture and run host telemetry only")
    parser.add_argument("--no-windows-firewall", action="store_true", help="Disable Windows Firewall log telemetry")
    parser.add_argument("--firewall-log", default=str(DEFAULT_FIREWALL_LOG), help="Windows Firewall log path")
    parser.add_argument("--firewall-read-existing", action="store_true", help="Read existing firewall log entries instead of tailing from end")
    parser.add_argument("--alerts-output", default="data/alerts/live_alerts.json", help="Live alerts JSON consumed by Streamlit")
    parser.add_argument("--events-output", default="data/live/live_events.jsonl", help="Telemetry history for evidence")
    parser.add_argument("--status-output", default="data/live/status.json", help="Runtime status file for Streamlit")
    parser.add_argument("--threat-intel", default="config/threat_intel.json", help="Local malicious domain/IP list for threat-intel matching")
    parser.add_argument("--keep-history", action="store_true", help="Keep previous live alerts/events instead of starting a fresh current session")
    parser.add_argument("--max-alerts", type=int, default=1000, help="Max alerts kept in dashboard file")
    parser.add_argument("--window-seconds", type=int, default=300, help="Network rolling detection window")
    parser.add_argument("--firewall-window-seconds", type=int, default=120, help="Firewall rolling detection window")
    parser.add_argument("--cooldown-seconds", type=int, default=120, help="Duplicate alert suppression period")
    parser.add_argument("--min-portscan-ports", type=int, default=5, help="Unique ports required for scan alert")
    parser.add_argument("--min-blocked-packets", type=int, default=20, help="Firewall dropped packets required for scan alert")
    parser.add_argument("--min-beacon-connections", type=int, default=8, help="Connections required for beaconing alert")
    parser.add_argument("--exfil-threshold-mb", type=int, default=50, help="Outbound MB in 120s required for exfil alert")
    parser.add_argument("--trusted-ip", action="append", default=[], help="Trusted IP to suppress. Can be used multiple times.")
    parser.add_argument("--send-elastic", action="store_true", help="Also send live alerts to Elasticsearch")
    args = parser.parse_args()

    signal.signal(signal.SIGINT, _handle_stop)
    signal.signal(signal.SIGTERM, _handle_stop)

    local_ips = get_local_ips()
    resolved_interfaces: list[str] = []
    if not args.no_packets:
        resolved_interfaces = resolve_interfaces(args.interface, args.interfaces, include_loopback=args.include_loopback)

    packet_detector = RollingLiveDetector(
        local_ips=local_ips,
        window_seconds=args.window_seconds,
        cooldown_seconds=args.cooldown_seconds,
        min_portscan_ports=args.min_portscan_ports,
        min_beacon_connections=args.min_beacon_connections,
        exfil_threshold_mb=args.exfil_threshold_mb,
        trusted_ips=args.trusted_ip,
        threat_intel_path=args.threat_intel,
    )
    firewall_detector = WindowsFirewallDetector(
        local_ips=local_ips,
        trusted_ips=args.trusted_ip,
        window_seconds=args.firewall_window_seconds,
        cooldown_seconds=args.cooldown_seconds,
        min_portscan_ports=args.min_portscan_ports,
        min_blocked_packets=args.min_blocked_packets,
    )

    # Start a fresh current session by default so old live alerts do not reappear
    # after closing/reopening the project. Previous alerts/events are archived.
    session_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    if not args.keep_history:
        history_dir = Path("data/history")
        history_dir.mkdir(parents=True, exist_ok=True)
        for live_path in [Path(args.alerts_output), Path(args.events_output)]:
            if live_path.exists() and live_path.stat().st_size > 0:
                archived = history_dir / f"{session_id}_{live_path.name}"
                try:
                    shutil.copy2(live_path, archived)
                except Exception:
                    pass
                try:
                    live_path.unlink()
                except Exception:
                    pass

    all_alerts = read_json_list(args.alerts_output) if args.keep_history else []
    seen_alert_ids = {a.get("alert_id") for a in all_alerts}
    telemetry_q: "queue.Queue[tuple[str, Any]]" = queue.Queue()

    started_at = time.time()
    status_base = {
        "running": True,
        "mode": "Hybrid NDR: packet + Windows host telemetry",
        "interface": ",".join(resolved_interfaces) if resolved_interfaces else "disabled",
        "interfaces": resolved_interfaces,
        "local_ips": sorted(local_ips),
        "trusted_ips": sorted(packet_detector.trusted_ips | firewall_detector.trusted_ips),
        "firewall_log": args.firewall_log,
        "windows_firewall_enabled": not args.no_windows_firewall,
        "packets_seen": 0,
        "firewall_events_seen": 0,
        "alerts_seen": len(all_alerts),
        "started_at_epoch": started_at,
        "message": "Hybrid monitor started.",
        "session_id": session_id,
        "current_session_only": not args.keep_history,
        "threat_intel": args.threat_intel,
    }
    atomic_write_json(args.status_output, status_base)

    print("=" * 84)
    print("HYBRID LIVE NDR MONITOR STARTED")
    print("=" * 84)
    print(f"Packet interfaces : {', '.join(resolved_interfaces) if resolved_interfaces else 'disabled'}")
    print(f"Firewall log      : {args.firewall_log if not args.no_windows_firewall else 'disabled'}")
    print(f"Local IPs         : {', '.join(sorted(local_ips)) or 'not detected'}")
    print(f"Trusted IPs       : {', '.join(sorted(packet_detector.trusted_ips | firewall_detector.trusted_ips)) or 'none'}")
    print("Detection sources : TShark/Npcap + Windows Defender Firewall log")
    print("Severity levels   : Critical / High / Normal")
    print(f"Session ID        : {session_id}")
    print(f"Current session   : {'fresh start' if not args.keep_history else 'keeping previous live history'}")
    print(f"Threat intel      : {args.threat_intel}")
    print("Press Ctrl+C to stop. Keep this terminal running while using Streamlit.")
    print("=" * 84)

    threads: list[threading.Thread] = []
    if not args.no_packets:
        t = threading.Thread(target=_packet_worker, args=(telemetry_q, resolved_interfaces, local_ips, args.capture_filter), daemon=True)
        t.start()
        threads.append(t)
    if not args.no_windows_firewall:
        t = threading.Thread(target=_firewall_worker, args=(telemetry_q, args.firewall_log, local_ips, args.firewall_read_existing), daemon=True)
        t.start()
        threads.append(t)

    packet_count = 0
    firewall_count = 0
    last_status_write = 0.0

    try:
        while not STOP:
            try:
                source, item = telemetry_q.get(timeout=1.0)
            except queue.Empty:
                # Periodic status even when no traffic arrives.
                now = time.time()
                if now - last_status_write >= 2:
                    status_base.update({
                        "running": True,
                        "packets_seen": packet_count,
                        "firewall_events_seen": firewall_count,
                        "alerts_seen": len(all_alerts),
                        "last_status_epoch": now,
                    })
                    atomic_write_json(args.status_output, status_base)
                    last_status_write = now
                continue

            if source == "error":
                print(f"[WARN] {item}", flush=True)
                status_base["last_warning"] = str(item)
                continue

            new_alert_dicts: list[dict[str, Any]] = []
            if source == "packet":
                packet_count += 1
                event_dict = item.to_dict()
                event_dict["telemetry_source"] = "tshark_packet"
                append_jsonl(args.events_output, event_dict)
                alerts = packet_detector.process(item)
            elif source == "firewall":
                firewall_count += 1
                event_dict = _firewall_event_to_live_row(item)
                append_jsonl(args.events_output, event_dict)
                alerts = firewall_detector.process(item)
            else:
                continue

            for alert in alerts:
                ad = alert.to_dict()
                if ad["alert_id"] not in seen_alert_ids:
                    seen_alert_ids.add(ad["alert_id"])
                    all_alerts.append(ad)
                    new_alert_dicts.append(ad)
                    print(
                        f"[ALERT] {ad['severity']:8} {ad['risk_score']:3} "
                        f"{ad['detection']} {ad['source_ip']} -> {ad['destination_ip']}",
                        flush=True,
                    )

            if new_alert_dicts:
                write_alerts(args.alerts_output, all_alerts, max_alerts=args.max_alerts)
                if args.send_elastic:
                    try:
                        send_alerts(new_alert_dicts)
                    except Exception as exc:
                        print(f"Elastic write failed: {exc}", flush=True)

            now = time.time()
            if now - last_status_write >= 2:
                status_base.update({
                    "running": True,
                    "packets_seen": packet_count,
                    "firewall_events_seen": firewall_count,
                    "alerts_seen": len(all_alerts),
                    "last_event_epoch": event_dict.get("timestamp"),
                    "last_event": event_dict,
                })
                atomic_write_json(args.status_output, status_base)
                last_status_write = now

    except KeyboardInterrupt:
        pass
    finally:
        status_base.update({
            "running": False,
            "packets_seen": packet_count,
            "firewall_events_seen": firewall_count,
            "alerts_seen": len(all_alerts),
            "stopped_at_epoch": time.time(),
        })
        atomic_write_json(args.status_output, status_base)
        write_alerts(args.alerts_output, all_alerts, max_alerts=args.max_alerts)
        print(f"Hybrid monitor stopped. Packets: {packet_count}. Firewall events: {firewall_count}. Alerts: {len(all_alerts)}")


if __name__ == "__main__":
    main()
