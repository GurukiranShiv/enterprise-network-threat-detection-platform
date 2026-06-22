import argparse
import json
from pathlib import Path
import sys

# Allows running directly: python detection_engine/main.py
PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from detection_engine.parsers.zeek_parser import load_zeek_logs
from detection_engine.parsers.suricata_parser import load_suricata_eve
from detection_engine.detectors import (
    port_scan,
    ssh_bruteforce,
    beaconing,
    dns_tunneling,
    data_exfiltration,
    lateral_movement,
    suricata_alerts,
)
from detection_engine.elastic_writer import send_alerts


def run(input_dir: str, output_path: str, send_elastic: bool = False):
    zeek = load_zeek_logs(input_dir)
    suri = load_suricata_eve(input_dir)

    alerts = []
    alerts.extend(port_scan.detect(zeek["conn"], suri))
    alerts.extend(ssh_bruteforce.detect(zeek["conn"], suri))
    alerts.extend(beaconing.detect(zeek["conn"]))
    alerts.extend(dns_tunneling.detect(zeek["dns"]))
    alerts.extend(data_exfiltration.detect(zeek["conn"]))
    alerts.extend(lateral_movement.detect(zeek["conn"]))
    alerts.extend(suricata_alerts.detect(suri))

    # Sort highest risk first for SOC-style triage.
    alert_dicts = sorted([a.to_dict() for a in alerts], key=lambda x: x["risk_score"], reverse=True)

    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(alert_dicts, indent=2), encoding="utf-8")

    print(f"Generated alerts: {len(alert_dicts)}")
    print(f"Output written to {out}")

    if send_elastic:
        send_alerts(alert_dicts)

    return alert_dicts


def main():
    parser = argparse.ArgumentParser(description="Enterprise Network Threat Detection Engine")
    parser.add_argument("--input", default="data/sample", help="Folder containing zeek_conn.log, zeek_dns.log, zeek_http.log, suricata_eve.json")
    parser.add_argument("--output", default="data/alerts/alerts.json", help="Output alerts JSON path")
    parser.add_argument("--send-elastic", action="store_true", help="Send generated alerts to Elasticsearch")
    args = parser.parse_args()

    run(args.input, args.output, args.send_elastic)


if __name__ == "__main__":
    main()
