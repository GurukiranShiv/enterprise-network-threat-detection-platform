from collections import defaultdict
from typing import List, Dict
from detection_engine.models import Alert
from detection_engine.utils import parse_ts, epoch_to_iso
from detection_engine.enrichment.mitre_mapper import map_detection
from detection_engine.scoring.risk_score import score_bruteforce, severity

FAIL_STATES = {"REJ", "RSTO", "RSTR", "S0"}


def detect(conn_rows: List[Dict[str, str]], suricata_events=None, threshold_attempts: int = 8) -> List[Alert]:
    suricata_events = suricata_events or []
    grouped = defaultdict(list)
    for row in conn_rows:
        if row.get("id.resp_p") == "22":
            state = row.get("conn_state", "")
            if state in FAIL_STATES or row.get("service") == "ssh":
                grouped[(row.get("id.orig_h", ""), row.get("id.resp_h", ""))].append(row)

    alerts = []
    for idx, ((src, dst), rows) in enumerate(grouped.items(), start=1):
        fail_rows = [r for r in rows if r.get("conn_state") in FAIL_STATES]
        if len(fail_rows) >= threshold_attempts:
            first_ts = min(parse_ts(r.get("ts", "0")) for r in rows)
            score = score_bruteforce(len(fail_rows), unique_usernames=1)
            suricata_signatures = [
                e.get("alert", {}).get("signature", "") for e in suricata_events
                if e.get("src_ip") == src and e.get("dest_ip") == dst and "ssh" in e.get("alert", {}).get("signature", "").lower()
            ]
            if suricata_signatures:
                score = min(100, score + 10)
            mitre = map_detection("SSH Brute Force")
            alerts.append(Alert(
                alert_id=f"NET-SSHBRUTE-{idx:04d}",
                timestamp=epoch_to_iso(first_ts),
                detection="SSH Brute Force",
                severity=severity(score),
                risk_score=score,
                source_ip=src,
                destination_ip=dst,
                mitre_technique=mitre["technique"],
                mitre_tactic=mitre["tactic"],
                evidence={
                    "failed_attempts": len(fail_rows),
                    "total_ssh_connections": len(rows),
                    "suricata_signatures": suricata_signatures,
                    "logic": "Repeated failed SSH connections from one source to one destination.",
                },
                recommended_action="Check whether the source is a scanner or compromised host. Review authentication logs, block the source if unauthorized, and confirm whether any login succeeded after repeated failures."
            ))
    return alerts
