# Port Scan Simulation

Run only inside your own lab.

```bash
nmap -sS -T4 <victim-ip>
```

Expected detection:

- Internal Port Scan
- MITRE T1046
- Zeek `conn.log` shows one source touching many destination ports
- Suricata may generate scan-related signatures
