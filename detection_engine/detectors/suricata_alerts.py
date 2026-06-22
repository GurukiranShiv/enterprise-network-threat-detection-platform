from typing import List, Dict, Any
from detection_engine.models import Alert
from detection_engine.utils import epoch_to_iso, parse_ts
from detection_engine.enrichment.mitre_mapper import map_detection
from detection_engine.scoring.risk_score import severity


def detect(events: List[Dict[str, Any]]) -> List[Alert]:
    alerts = []
    counter = 1
    for event in events:
        if event.get("event_type") != "alert":
            continue
        alert = event.get("alert", {})
        sig = alert.get("signature", "Suricata Alert")
        sev = int(alert.get("severity", 3) or 3)
        score = {1: 90, 2: 75, 3: 55, 4: 35}.get(sev, 50)
        mitre = map_detection("Suricata IDS Alert")
        alerts.append(Alert(
            alert_id=f"IDS-SURICATA-{counter:04d}",
            timestamp=event.get("timestamp") or epoch_to_iso(parse_ts(event.get("ts", "0"))),
            detection="Suricata IDS Alert",
            severity=severity(score),
            risk_score=score,
            source_ip=event.get("src_ip", ""),
            destination_ip=event.get("dest_ip", ""),
            mitre_technique=mitre["technique"],
            mitre_tactic=mitre["tactic"],
            evidence={
                "signature": sig,
                "category": alert.get("category", ""),
                "signature_id": alert.get("signature_id", ""),
                "rev": alert.get("rev", ""),
                "protocol": event.get("proto", ""),
                "destination_port": event.get("dest_port", ""),
                "logic": "Raw IDS alert normalized for SOC triage.",
            },
            recommended_action="Correlate this IDS alert with Zeek network telemetry and endpoint activity before escalation."
        ))
        counter += 1
    return alerts
