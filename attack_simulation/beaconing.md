# Beaconing Simulation

Run only inside your own lab.

```bash
while true; do curl http://<server-ip>/checkin; sleep 60; done
```

Expected detection:

- Beaconing / C2-Like Traffic
- MITRE T1071
- Regular connection intervals
