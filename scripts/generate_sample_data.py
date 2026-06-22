from pathlib import Path
import json
import random
from datetime import datetime, timedelta, timezone

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "data" / "sample"
OUT.mkdir(parents=True, exist_ok=True)

base = datetime(2026, 6, 21, 1, 0, 0, tzinfo=timezone.utc)

def ts(seconds):
    return str((base + timedelta(seconds=seconds)).timestamp())

conn_fields = ["ts","uid","id.orig_h","id.orig_p","id.resp_h","id.resp_p","proto","service","duration","orig_bytes","resp_bytes","conn_state"]
dns_fields = ["ts","uid","id.orig_h","id.resp_h","query","qtype_name","rcode_name","answers"]
http_fields = ["ts","uid","id.orig_h","id.resp_h","method","host","uri","status_code","user_agent","request_body_len","response_body_len"]

conn = []
dns = []
http = []
eve = []
uid = 1000

def add_conn(sec, src, dst, dport, service="-", state="SF", orig_bytes=300, resp_bytes=800, proto="tcp"):
    global uid
    uid += 1
    conn.append([ts(sec), f"C{uid}", src, str(random.randint(30000, 60999)), dst, str(dport), proto, service, "0.10", str(orig_bytes), str(resp_bytes), state])
    return f"C{uid}"

def add_dns(sec, src, resolver, query, rcode="NOERROR"):
    global uid
    uid += 1
    dns.append([ts(sec), f"D{uid}", src, resolver, query, "A", rcode, "93.184.216.34"])

def add_http(sec, src, dst, host, uri, req=100, resp=1000):
    uid_val = add_conn(sec, src, dst, 80, "http", "SF", req, resp)
    http.append([ts(sec), uid_val, src, dst, "GET", host, uri, "200", "lab-client/1.0", str(req), str(resp)])

# Normal baseline traffic
normal_hosts = ["10.10.10.20", "10.10.10.21", "10.10.10.22", "10.10.10.23"]
normal_dests = [("93.184.216.34", 80, "http"), ("142.250.190.14", 443, "ssl"), ("52.96.0.10", 443, "ssl")]
for i in range(80):
    src = random.choice(normal_hosts)
    dst, port, svc = random.choice(normal_dests)
    add_conn(i * 13, src, dst, port, svc, "SF", random.randint(200, 2000), random.randint(800, 9000))
    if i % 5 == 0:
        add_dns(i * 13, src, "10.10.10.2", random.choice(["microsoft.com", "office.com", "github.com", "elastic.co"]))

# Detection 1: Port scan from Kali
for p in range(1, 36):
    add_conn(1200 + p, "10.10.10.50", "10.10.10.30", p, "-", "S0", 0, 0)
eve.append({"timestamp": (base + timedelta(seconds=1210)).isoformat(), "event_type": "alert", "src_ip": "10.10.10.50", "src_port": 44444, "dest_ip": "10.10.10.30", "dest_port": 80, "proto": "TCP", "alert": {"signature_id": 1000001, "rev": 1, "signature": "ET SCAN Nmap Scripting Engine User-Agent Detected", "category": "Attempted Information Leak", "severity": 2}})

# Detection 2: SSH brute force
for i in range(15):
    add_conn(1600 + i * 3, "10.10.10.50", "10.10.10.40", 22, "ssh", "REJ", 0, 0)
eve.append({"timestamp": (base + timedelta(seconds=1630)).isoformat(), "event_type": "alert", "src_ip": "10.10.10.50", "src_port": 50100, "dest_ip": "10.10.10.40", "dest_port": 22, "proto": "TCP", "alert": {"signature_id": 1000002, "rev": 1, "signature": "GPL ATTACK_RESPONSE SSH Brute Force Attempt", "category": "Potentially Bad Traffic", "severity": 2}})

# Detection 3: Beaconing-like traffic
for i in range(8):
    add_http(2200 + i * 60 + random.choice([-1, 0, 1]), "10.10.10.31", "198.51.100.25", "updates-check.example", "/checkin", 80, 120)

# Detection 4: Suspicious DNS
long_queries = [
    "a8f7d9e2b4c6f1a0d3e5c7b9a1f4e6d8c2b5a9f7e1c3d6b8.payload.lab.example",
    "x1q9z8m7n6b5v4c3p2o1i0u9y8t7r6e5w4q3s2d1f0.data.exfil.example",
]
for i, q in enumerate(long_queries):
    add_dns(2800 + i * 5, "10.10.10.31", "10.10.10.2", q, "NOERROR")

# Detection 5: Exfiltration
add_conn(3400, "10.10.10.32", "8.8.4.4", 443, "ssl", "SF", 2500000, 5000)

# Detection 6: Lateral movement-like admin traffic
for i, dst in enumerate(["10.10.10.40", "10.10.10.41", "10.10.10.42", "10.10.10.43"]):
    add_conn(3900 + i * 4, "10.10.10.33", dst, 445, "smb", "SF", 900, 1200)
    add_conn(3910 + i * 4, "10.10.10.33", dst, 22, "ssh", "SF", 500, 900)

# Write files
with (OUT / "zeek_conn.log").open("w", encoding="utf-8") as f:
    f.write("\t".join(conn_fields) + "\n")
    for row in conn:
        f.write("\t".join(row) + "\n")

with (OUT / "zeek_dns.log").open("w", encoding="utf-8") as f:
    f.write("\t".join(dns_fields) + "\n")
    for row in dns:
        f.write("\t".join(row) + "\n")

with (OUT / "zeek_http.log").open("w", encoding="utf-8") as f:
    f.write("\t".join(http_fields) + "\n")
    for row in http:
        f.write("\t".join(row) + "\n")

with (OUT / "suricata_eve.json").open("w", encoding="utf-8") as f:
    for event in eve:
        f.write(json.dumps(event) + "\n")

print(f"Sample telemetry written to {OUT}")
