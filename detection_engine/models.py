from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from typing import Any, Dict

@dataclass
class Alert:
    alert_id: str
    timestamp: str
    detection: str
    severity: str
    risk_score: int
    source_ip: str
    destination_ip: str
    mitre_technique: str
    mitre_tactic: str
    evidence: Dict[str, Any]
    recommended_action: str
    status: str = "Open"
    analyst_verdict: str = "Needs Review"
    confidence: str = "Medium"
    triage_priority: str = "P3"
    false_positive_considerations: str = "Review local context, expected applications, and asset role before escalation."

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()
