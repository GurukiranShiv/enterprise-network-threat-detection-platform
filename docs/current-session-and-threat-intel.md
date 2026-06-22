# Current Session and Threat Intel Behavior

## Why old alerts used to reappear

Live alerts are stored on disk in `data/alerts/live_alerts.json` so analysts can reopen the dashboard and keep evidence. That is useful for investigations, but confusing during testing.

This version starts a fresh current session by default. Older live alerts and packet events are copied into `data/history/` and removed from the current dashboard. To keep old alerts, start the monitor with `--keep-history`.

## Why detection can take time

Some detections are immediate, such as threat-intel domain/IP matches and suspicious port matches. Others need a rolling window, such as port scans, beaconing, and large transfers. Rolling windows reduce false positives because one packet is usually not enough evidence.

Dashboard refresh is also controlled by the Streamlit refresh interval. If refresh is set to 2 seconds, an alert may appear a few seconds after the monitor prints it.

## Ping and HTTP headers

ICMP ping does not contain HTTP headers. If you `ping malicious.test`, the detector can alert on DNS resolution or malicious IP metadata, but it cannot see an HTTP header because ping is not HTTP.

To test HTTP Host header visibility, use unencrypted HTTP:

```powershell
curl http://malicious.test
```

HTTPS encrypts URL paths and most headers. The detector may still see DNS query names or TLS SNI when visible.
