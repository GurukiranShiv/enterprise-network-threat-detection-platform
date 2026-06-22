# Alert Triage and False-Positive Tuning

This project captures live packet metadata continuously, but it should not turn every packet into an incident.

## What is captured

The live monitor records packet metadata such as:

- timestamp
- direction
- protocol
- source/destination IP
- source/destination port
- length
- DNS query, HTTP host, or TLS SNI when visible

HTTPS payloads are not decrypted.

## What is suppressed from alerting

The tuned detector suppresses common background traffic from becoming an incident:

- gateway/router chatter, such as `192.168.x.1`
- multicast destinations such as `224.0.0.251`
- IPv6 multicast such as `ff02::fb`
- link-local addresses such as `169.254.x.x` and `fe80::/10`
- mDNS, SSDP, LLMNR, DHCP, NetBIOS discovery ports
- common web/DNS/NTP/mail ports such as 53, 80, 123, 443, 587, 993, 995
- tiny ACK/keepalive packets

## Why this matters

Your laptop produces background traffic even when you do nothing. Windows services, browsers, cloud sync, antivirus, updates, router discovery, and VS Code extensions all create network events. A real detection project must distinguish telemetry from actionable security incidents.

## Analyst workflow

1. Start in **Critical Alerts**.
2. Check source and destination.
3. Determine whether the source is your laptop, router, or unknown device.
4. Review the rule reason and evidence.
5. Check false-positive considerations.
6. Use the PowerShell checklist in Incident Details to validate process and connection context.
7. If the source is trusted, rerun the monitor with `--trusted-ip <ip>`.

Example:

```powershell
python -m live_monitor.run_live_monitor --interface 6 --trusted-ip 192.168.4.1
```

## Good interview explanation

“In the first live version, the monitor captured real traffic but generated false positives on router, multicast, and local discovery traffic. I tuned the detection logic to keep packet visibility while suppressing benign network noise. The platform now separates raw telemetry from actionable incidents and provides analyst triage fields such as confidence, priority, verdict, false-positive considerations, and recommended investigation steps.”
