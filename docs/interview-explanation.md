# Interview Explanation

## 60-Second Version

I built a network threat detection and behavior fingerprinting platform that analyzes Zeek-style network telemetry and Suricata-style IDS alerts. The Python detection engine identifies suspicious behaviors such as port scanning, SSH brute force, beaconing, DNS tunneling, suspicious outbound transfers, and lateral movement-like internal communication. Each alert is enriched with risk scoring, MITRE ATT&CK mapping, evidence, and recommended analyst actions. I visualized the results using a Streamlit SOC dashboard and optionally indexed the alerts into Elasticsearch for Kibana-based investigation.

## Why This Is Not Just a UI Project

The UI only visualizes detection output. The main work is in parsing telemetry, engineering detection logic, scoring risk, explaining evidence, and mapping alerts to ATT&CK techniques.

## How I Would Explain Beaconing Detection

I grouped connections by source, destination, destination port, and service. Then I sorted timestamps and calculated intervals between connections. If a host contacted the same destination repeatedly at a stable interval, such as every 60 seconds, I flagged it as beaconing or C2-like behavior. This avoids relying only on reputation and demonstrates behavior-based detection.

## How I Would Explain False Positive Reduction

I would tune detections using allowlists and context. For example, a vulnerability scanner may trigger port scan logic, a backup system may trigger exfiltration logic, and monitoring agents may trigger beaconing logic. The goal is not only to detect suspicious behavior but to make the alert explainable and tunable.
