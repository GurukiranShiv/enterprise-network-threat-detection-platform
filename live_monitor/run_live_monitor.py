from __future__ import annotations

import argparse
import signal
import sys
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from detection_engine.elastic_writer import send_alerts
from live_monitor.live_detector import RollingLiveDetector
from live_monitor.network_utils import get_local_ips
from live_monitor.tshark_interface import resolve_interfaces, stream_events
from live_monitor.writers import append_jsonl, atomic_write_json, read_json_list, write_alerts

STOP = False


def _handle_stop(signum, frame):  # type: ignore[no-untyped-def]
    global STOP
    STOP = True
    print("\nStopping live monitor...", flush=True)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Real-time network threat monitor using TShark/Npcap packet metadata."
    )
    parser.add_argument("--interface", default=None, help='TShark interface number/name, or "all" to capture all Npcap interfaces. Example: 6 or all')
    parser.add_argument("--interfaces", default=None, help='Comma-separated interface numbers/names, e.g. "6,9,11"')
    parser.add_argument("--include-loopback", action="store_true", help="Include loopback when --interface all is used")
    parser.add_argument("--capture-filter", default=None, help='Optional BPF filter, e.g. "ip and not broadcast"')
    parser.add_argument("--alerts-output", default="data/alerts/live_alerts.json", help="Live alerts JSON consumed by Streamlit")
    parser.add_argument("--events-output", default="data/live/live_events.jsonl", help="Packet metadata history for evidence")
    parser.add_argument("--status-output", default="data/live/status.json", help="Runtime status file for Streamlit")
    parser.add_argument("--max-alerts", type=int, default=500, help="Max alerts kept in JSON dashboard file")
    parser.add_argument("--max-events-jsonl", type=int, default=0, help="0 means append unlimited event JSONL history")
    parser.add_argument("--window-seconds", type=int, default=300, help="Rolling detection window")
    parser.add_argument("--cooldown-seconds", type=int, default=300, help="Duplicate alert suppression period")
    parser.add_argument("--min-portscan-ports", type=int, default=8, help="Unique ports/signals in 60s required for port-scan alert")
    parser.add_argument("--min-beacon-connections", type=int, default=8, help="Connections required for beaconing alert")
    parser.add_argument("--exfil-threshold-mb", type=int, default=50, help="Outbound MB in 120s required for exfil alert")
    parser.add_argument("--trusted-ip", action="append", default=[], help="Trusted IP to suppress for local gateway/scanner noise. Can be used multiple times.")
    parser.add_argument("--send-elastic", action="store_true", help="Also send live alerts to Elasticsearch")
    args = parser.parse_args()

    signal.signal(signal.SIGINT, _handle_stop)
    signal.signal(signal.SIGTERM, _handle_stop)

    local_ips = get_local_ips()
    resolved_interfaces = resolve_interfaces(args.interface, args.interfaces, include_loopback=args.include_loopback)

    detector = RollingLiveDetector(
        local_ips=local_ips,
        window_seconds=args.window_seconds,
        cooldown_seconds=args.cooldown_seconds,
        min_portscan_ports=args.min_portscan_ports,
        min_beacon_connections=args.min_beacon_connections,
        exfil_threshold_mb=args.exfil_threshold_mb,
        trusted_ips=args.trusted_ip,
    )

    all_alerts = read_json_list(args.alerts_output)
    seen_alert_ids = {a.get("alert_id") for a in all_alerts}

    print("=" * 78)
    print("LIVE NETWORK THREAT MONITOR STARTED")
    print("=" * 78)
    print(f"Interfaces      : {', '.join(resolved_interfaces)}")
    print(f"Local IPs       : {', '.join(sorted(local_ips)) or 'not detected'}")
    print(f"Alerts output   : {args.alerts_output}")
    print(f"Events output   : {args.events_output}")
    print(f"Trusted IPs     : {', '.join(sorted(detector.trusted_ips)) or 'none'}")
    print("Detection mode  : Production NDR")
    print("Severity levels : Critical / High / Normal")
    print(f"Elastic enabled : {args.send_elastic}")
    print("Press Ctrl+C to stop. Keep this terminal running while using Streamlit.")
    print("=" * 78)

    packet_count = 0
    alert_count = len(all_alerts)
    started_at = time.time()
    last_status_write = 0.0

    # Write an immediate running status so Streamlit does not show "not running"
    # while waiting for the first packet.
    atomic_write_json(
        args.status_output,
        {
            "running": True,
            "interface": ",".join(resolved_interfaces),
            "interfaces": resolved_interfaces,
            "local_ips": sorted(local_ips),
            "trusted_ips": sorted(detector.trusted_ips),
            "packets_seen": packet_count,
            "alerts_seen": len(all_alerts),
            "started_at_epoch": started_at,
            "message": "Live monitor started and waiting for packets.",
        },
    )

    try:
        for event in stream_events(resolved_interfaces, local_ips, args.capture_filter):
            if STOP:
                break
            packet_count += 1

            event_dict = event.to_dict()
            append_jsonl(args.events_output, event_dict)

            new_alerts = detector.process(event)
            if new_alerts:
                new_alert_dicts = []
                for alert in new_alerts:
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
                    alert_count += len(new_alert_dicts)
                    write_alerts(args.alerts_output, all_alerts, max_alerts=args.max_alerts)
                    if args.send_elastic:
                        try:
                            send_alerts(new_alert_dicts)
                        except Exception as exc:
                            print(f"Elastic write failed: {exc}", flush=True)

            now = time.time()
            if now - last_status_write >= 2:
                atomic_write_json(
                    args.status_output,
                    {
                        "running": True,
                        "interface": ",".join(resolved_interfaces),
            "interfaces": resolved_interfaces,
                        "local_ips": sorted(local_ips),
                        "trusted_ips": sorted(detector.trusted_ips),
                        "packets_seen": packet_count,
                        "alerts_seen": len(all_alerts),
                        "started_at_epoch": started_at,
                        "last_event_epoch": event.timestamp,
                        "last_event": event_dict,
                    },
                )
                last_status_write = now

    except RuntimeError as exc:
        print(f"\nERROR: {exc}", file=sys.stderr)
        atomic_write_json(
            args.status_output,
            {
                "running": False,
                "error": str(exc),
                "interface": ",".join(resolved_interfaces),
            "interfaces": resolved_interfaces,
                "local_ips": sorted(local_ips),
                "trusted_ips": sorted(detector.trusted_ips),
                "packets_seen": packet_count,
                "alerts_seen": len(all_alerts),
            },
        )
        sys.exit(1)
    finally:
        atomic_write_json(
            args.status_output,
            {
                "running": False,
                "interface": ",".join(resolved_interfaces),
            "interfaces": resolved_interfaces,
                "local_ips": sorted(local_ips),
                "trusted_ips": sorted(detector.trusted_ips),
                "packets_seen": packet_count,
                "alerts_seen": len(all_alerts),
                "started_at_epoch": started_at,
                "stopped_at_epoch": time.time(),
            },
        )
        write_alerts(args.alerts_output, all_alerts, max_alerts=args.max_alerts)
        print(f"Live monitor stopped. Packets seen: {packet_count}. Alerts available: {len(all_alerts)}")


if __name__ == "__main__":
    main()
