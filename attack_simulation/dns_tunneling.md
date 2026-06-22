# Suspicious DNS Simulation

Run only inside your own lab.

```bash
nslookup a8f7d9e2b4c6f1a0d3e5c7b9a1f4e6d8c2b5a9f7e1c3d6b8.payload.lab.example
```

Expected detection:

- Suspicious DNS / Possible DNS Tunneling
- MITRE T1071.004
- Long or high-entropy DNS query
