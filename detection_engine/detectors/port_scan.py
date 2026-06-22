from collections import defaultdict
from typing import List, Dict
from detection_engine.models import Alert
from detection_engine.utils import parse_ts, epoch_to_iso
from detection_engine.enrichment.mitre_mapper import map_detection
from detection_engine.scoring.risk_score import score_port_scan, severity


def detect(conn_rows: List[Dict[str, str]], suricata_events=None, threshold_ports: int = 15) -> List[Alert]:
    suricata_events = suricata_events or []
    grouped = defaultdict(list)
    for row in conn_rows:
        src = row.get("id.orig_h", "")
        dst = row.get("id.resp_h", "")
        grouped[(src, dst)].append(row)

    alerts = []
    for idx, ((src, dst), rows) in enumerate(grouped.items(), start=1):
        ports = {r.get("id.resp_p", "") for r in rows if r.get("id.resp_p")}
        if len(ports) >= threshold_ports:
            suricata_confirmed = any(
                e.get("src_ip") == src and e.get("dest_ip") == dst and "scan" in e.get("alert", {}).get("signature", "").lower()
                for e in suricata_events
            )
            first_ts = min(parse_ts(r.get("ts", "0")) for r in rows)
            score = score_port_scan(len(ports), suricata_confirmed)
            mitre = map_detection("Internal Port Scan")
            alerts.append(Alert(
                alert_id=f"NET-PORTSCAN-{idx:04d}",
                timestamp=epoch_to_iso(first_ts),
                detection="Internal Port Scan",
                severity=severity(score),
                risk_score=score,
                source_ip=src,
                destination_ip=dst,
                mitre_technique=mitre["technique"],
                mitre_tactic=mitre["tactic"],
                evidence={
                    "unique_ports": len(ports),
                    "sample_ports": sorted(list(ports), key=lambda x: int(x) if x.isdigit() else 0)[:25],
                    "connection_count": len(rows),
                    "suricata_confirmed": suricata_confirmed,
                    "logic": "Same source connected to many destination ports on the same host.",
                },
                recommended_action="Validate whether the source host is authorized to scan. If unauthorized, isolate or investigate the source endpoint and review recent user/process activity."
            ))
    return alerts
