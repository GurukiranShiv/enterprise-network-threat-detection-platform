from collections import defaultdict
from statistics import mean, pstdev
from typing import List, Dict
from detection_engine.models import Alert
from detection_engine.utils import parse_ts, epoch_to_iso
from detection_engine.enrichment.mitre_mapper import map_detection
from detection_engine.scoring.risk_score import score_beaconing, severity


def detect(conn_rows: List[Dict[str, str]], min_connections: int = 5, max_stddev: float = 6.0) -> List[Alert]:
    grouped = defaultdict(list)
    for row in conn_rows:
        src = row.get("id.orig_h", "")
        dst = row.get("id.resp_h", "")
        port = row.get("id.resp_p", "")
        service = row.get("service", "") or "unknown"
        grouped[(src, dst, port, service)].append(row)

    alerts = []
    counter = 1
    for (src, dst, port, service), rows in grouped.items():
        times = sorted(parse_ts(r.get("ts", "0")) for r in rows)
        if len(times) < min_connections:
            continue
        intervals = [round(times[i] - times[i-1], 2) for i in range(1, len(times))]
        if len(intervals) < min_connections - 1:
            continue
        avg_interval = mean(intervals)
        stddev = pstdev(intervals) if len(intervals) > 1 else 0.0
        if 20 <= avg_interval <= 180 and stddev <= max_stddev:
            score = score_beaconing(len(times), avg_interval, stddev)
            mitre = map_detection("Beaconing / C2-Like Traffic")
            alerts.append(Alert(
                alert_id=f"NET-BEACON-{counter:04d}",
                timestamp=epoch_to_iso(times[0]),
                detection="Beaconing / C2-Like Traffic",
                severity=severity(score),
                risk_score=score,
                source_ip=src,
                destination_ip=dst,
                mitre_technique=mitre["technique"],
                mitre_tactic=mitre["tactic"],
                evidence={
                    "destination_port": port,
                    "service": service,
                    "connection_count": len(times),
                    "average_interval_seconds": round(avg_interval, 2),
                    "interval_stddev_seconds": round(stddev, 2),
                    "intervals": intervals[:20],
                    "logic": "Repeated connections to the same destination occur at a regular interval.",
                },
                recommended_action="Investigate the process or host creating periodic outbound communication. Check endpoint telemetry, DNS history, proxy logs, and destination reputation."
            ))
            counter += 1
    return alerts
