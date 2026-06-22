from typing import List, Dict
from detection_engine.models import Alert
from detection_engine.utils import parse_ts, epoch_to_iso, shannon_entropy
from detection_engine.enrichment.mitre_mapper import map_detection
from detection_engine.scoring.risk_score import score_dns, severity


def subdomain_depth(query: str) -> int:
    parts = [p for p in query.split(".") if p]
    return max(0, len(parts) - 2)


def detect(dns_rows: List[Dict[str, str]], min_length: int = 70, min_entropy: float = 4.1) -> List[Alert]:
    alerts = []
    for idx, row in enumerate(dns_rows, start=1):
        query = row.get("query", "")
        ent = shannon_entropy(query)
        depth = subdomain_depth(query)
        suspicious = len(query) >= min_length or (ent >= min_entropy and depth >= 3)
        if suspicious:
            score = score_dns(len(query), ent, depth)
            mitre = map_detection("Suspicious DNS / Possible DNS Tunneling")
            alerts.append(Alert(
                alert_id=f"NET-DNS-{idx:04d}",
                timestamp=epoch_to_iso(parse_ts(row.get("ts", "0"))),
                detection="Suspicious DNS / Possible DNS Tunneling",
                severity=severity(score),
                risk_score=score,
                source_ip=row.get("id.orig_h", ""),
                destination_ip=row.get("id.resp_h", ""),
                mitre_technique=mitre["technique"],
                mitre_tactic=mitre["tactic"],
                evidence={
                    "query": query,
                    "query_length": len(query),
                    "entropy": round(ent, 3),
                    "subdomain_depth": depth,
                    "rcode": row.get("rcode_name", ""),
                    "logic": "Long or high-entropy DNS query with deep subdomain structure.",
                },
                recommended_action="Review DNS query history from the host, identify the process creating the queries, and block/inspect the domain if unauthorized."
            ))
    return alerts
