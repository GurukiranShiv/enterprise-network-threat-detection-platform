# Detection Logic

## 1. Internal Port Scan

**Signal:** Same source connects to many ports on one destination.

**Evidence fields:** `id.orig_h`, `id.resp_h`, `id.resp_p`, `conn_state`.

**False positives:** Authorized vulnerability scanners, inventory tools, security testing.

## 2. SSH Brute Force

**Signal:** Repeated failed SSH connections from one source to one destination.

**Evidence fields:** destination port `22`, `conn_state`, Suricata SSH signatures.

**False positives:** Misconfigured automation, expired credentials, monitoring tools.

## 3. Beaconing / C2-Like Traffic

**Signal:** Same source contacts same destination at stable intervals.

**Evidence fields:** timestamp intervals, destination IP, port, service.

**False positives:** Update agents, EDR telemetry, health checks.

## 4. Suspicious DNS / Possible DNS Tunneling

**Signal:** Long DNS queries, high entropy, deep subdomain structure.

**Evidence fields:** query length, entropy, subdomain depth.

**False positives:** CDNs, tracking domains, legitimate telemetry.

## 5. Suspicious Outbound Data Transfer

**Signal:** Large outbound transfer from internal source to external destination.

**Evidence fields:** `orig_bytes`, destination IP, service, port.

**False positives:** Backups, file uploads, patch distribution.

## 6. Lateral Movement-Like Internal Communication

**Signal:** Internal host contacts multiple internal destinations over admin ports.

**Evidence fields:** destination count, admin ports 22/445/3389/5985.

**False positives:** Admin jump boxes, patch servers, vulnerability scanners.
