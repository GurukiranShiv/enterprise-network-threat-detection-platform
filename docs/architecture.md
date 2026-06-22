# Architecture

## Goal

The platform detects suspicious network behavior using raw network telemetry and normalized IDS alerts.

## Core Pipeline

```text
Zeek conn/dns/http logs
        +
Suricata eve.json alerts
        ↓
Python parsers
        ↓
Detection modules
        ↓
Risk scoring
        ↓
MITRE ATT&CK enrichment
        ↓
JSON alerts
        ↓
Streamlit dashboard / Elasticsearch / Kibana
```

## Why This Design Is Realistic

In a real SOC, analysts rarely rely on one tool. Zeek provides rich protocol metadata, Suricata provides signature-based IDS alerts, and Elastic/Kibana provides search and visualization. The Python engine represents custom detection engineering that many teams build to close gaps not covered by default SIEM rules.
