from collections import defaultdict
from typing import List, Dict
from detection_engine.models import Alert
from detection_engine.utils import parse_ts, epoch_to_iso, is_internal_ip
from detection_engine.enrichment.mitre_mapper import map_detection
from detection_engine.scoring.risk_score import score_lateral, severity

ADMIN_PORTS = {"22", "445", "3389", "5985", "5986"}


def detect(conn_rows: List[Dict[str, str]], min_destinations: int = 3) -> List[Alert]:
    grouped = defaultdict(list)
    for row in conn_rows:
        src = row.get("id.orig_h", "")
        dst = row.get("id.resp_h", "")
        port = row.get("id.resp_p", "")
        if is_internal_ip(src) and is_internal_ip(dst) and port in ADMIN_PORTS:
            grouped[src].append(row)

    alerts = []
    for idx, (src, rows) in enumerate(grouped.items(), start=1):
        destinations = {r.get("id.resp_h", "") for r in rows}
        ports = {r.get("id.resp_p", "") for r in rows}
        if len(destinations) >= min_destinations:
            first_ts = min(parse_ts(r.get("ts", "0")) for r in rows)
            score = score_lateral(len(destinations), len(ports))
            mitre = map_detection("Lateral Movement-Like Internal Communication")
            alerts.append(Alert(
                alert_id=f"NET-LATERAL-{idx:04d}",
                timestamp=epoch_to_iso(first_ts),
                detection="Lateral Movement-Like Internal Communication",
                severity=severity(score),
                risk_score=score,
                source_ip=src,
                destination_ip=", ".join(sorted(destinations)),
                mitre_technique=mitre["technique"],
                mitre_tactic=mitre["tactic"],
                evidence={
                    "unique_internal_destinations": len(destinations),
                    "admin_ports_observed": sorted(list(ports)),
                    "connection_count": len(rows),
                    "logic": "One internal host contacted multiple internal peers using administrative/service ports.",
                },
                recommended_action="Verify whether the source host is an admin/jump server. If not expected, check for credential misuse, remote execution tools, and endpoint alerts."
            ))
    return alerts
