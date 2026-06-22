from typing import List, Dict
from detection_engine.models import Alert
from detection_engine.utils import parse_ts, epoch_to_iso, is_internal_ip
from detection_engine.enrichment.mitre_mapper import map_detection
from detection_engine.scoring.risk_score import score_exfil, severity


def detect(conn_rows: List[Dict[str, str]], byte_threshold: int = 500_000) -> List[Alert]:
    alerts = []
    counter = 1
    for row in conn_rows:
        src = row.get("id.orig_h", "")
        dst = row.get("id.resp_h", "")
        try:
            orig_bytes = int(float(row.get("orig_bytes") or 0))
        except Exception:
            orig_bytes = 0
        if orig_bytes >= byte_threshold and is_internal_ip(src) and not is_internal_ip(dst):
            score = score_exfil(orig_bytes, unusual_destination=True)
            mitre = map_detection("Suspicious Outbound Data Transfer")
            alerts.append(Alert(
                alert_id=f"NET-EXFIL-{counter:04d}",
                timestamp=epoch_to_iso(parse_ts(row.get("ts", "0"))),
                detection="Suspicious Outbound Data Transfer",
                severity=severity(score),
                risk_score=score,
                source_ip=src,
                destination_ip=dst,
                mitre_technique=mitre["technique"],
                mitre_tactic=mitre["tactic"],
                evidence={
                    "destination_port": row.get("id.resp_p", ""),
                    "service": row.get("service", ""),
                    "orig_bytes": orig_bytes,
                    "resp_bytes": row.get("resp_bytes", ""),
                    "logic": "Large outbound transfer from internal source to external destination.",
                },
                recommended_action="Confirm whether the transfer was authorized. Review user activity, destination ownership, file access logs, and proxy/firewall telemetry."
            ))
            counter += 1
    return alerts
