"""Small parser-only test. This does not capture traffic; it validates live detector logic.
Run: python scripts/test_live_dns_event.py
"""
from pathlib import Path
import sys
import time

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from live_monitor.live_detector import RollingLiveDetector
from live_monitor.models import LivePacketEvent

local_ip = "192.168.1.20"
detector = RollingLiveDetector(local_ips={local_ip})
event = LivePacketEvent(
    timestamp=time.time(),
    protocol="DNS",
    src_ip=local_ip,
    dst_ip="8.8.8.8",
    src_port=53000,
    dst_port=53,
    length=180,
    dns_query="ajskd83ksla9s8d7f6s5d4a3s2q1w0e9r8t7y6u5i4o3p2.long.example.com",
    direction="outbound",
)
alerts = detector.process(event)
print(f"Generated test alerts: {len(alerts)}")
for alert in alerts:
    print(alert.to_dict())
