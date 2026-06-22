import os
from datetime import datetime, timezone
from typing import List, Dict, Any


def send_alerts(alerts: List[Dict[str, Any]], elastic_url: str = None, index_prefix: str = None) -> None:
    elastic_url = elastic_url or os.getenv("ELASTIC_URL", "http://localhost:9200")
    index_prefix = index_prefix or os.getenv("ELASTIC_INDEX_PREFIX", "network-threat-alerts")
    index_name = f"{index_prefix}-{datetime.now(timezone.utc).strftime('%Y.%m.%d')}"

    try:
        from elasticsearch import Elasticsearch
        from elasticsearch.helpers import bulk
    except Exception as exc:
        print(f"[elastic] Python elasticsearch package not available: {exc}")
        return

    try:
        es = Elasticsearch(elastic_url, request_timeout=30)
        if not es.ping():
            print(f"[elastic] Could not connect to {elastic_url}")
            return
        actions = [
            {"_index": index_name, "_source": alert}
            for alert in alerts
        ]
        if actions:
            bulk(es, actions)
        print(f"[elastic] Sent {len(actions)} alerts to index {index_name}")
    except Exception as exc:
        print(f"[elastic] Failed to send alerts: {exc}")
