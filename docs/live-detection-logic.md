# Live Detection Logic

The live monitor evaluates packet metadata as it streams from TShark.

## Rolling Windows

- Port scan: last 60 seconds
- Data exfiltration: last 120 seconds
- Lateral movement: last 120 seconds
- Beaconing: default 300-second rolling window

## Alert Deduplication

The detector suppresses duplicate alerts using a cooldown period so the same behavior does not flood the dashboard.

## Detections

### Live Suspicious DNS

Triggers when a DNS query is long, deep, or high entropy.

### Live Beaconing

Triggers when the same source repeatedly connects to the same external destination at regular intervals.

### Live Port Scan

Triggers when one source contacts many ports on the same destination in a short time.

### Live Suspicious Outbound Data Transfer

Triggers when outbound packet volume to an external destination crosses the threshold.

### Live Lateral Movement-Like Communication

Triggers when an internal host contacts multiple internal peers or administrative ports.

### Live Unusual External Port

Triggers when outbound traffic goes to uncommon external ports.
