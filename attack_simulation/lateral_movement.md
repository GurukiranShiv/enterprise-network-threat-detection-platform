# Lateral Movement-Like Simulation

Run only inside your own lab.

```bash
for host in 10.10.10.40 10.10.10.41 10.10.10.42; do nc -vz $host 445; done
```

Expected detection:

- Lateral Movement-Like Internal Communication
- MITRE T1021
- One internal host contacting multiple internal peers over admin ports
