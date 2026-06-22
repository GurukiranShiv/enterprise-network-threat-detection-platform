# Final Stable Hybrid NDR Detection Profile

This build keeps the useful behavior from earlier versions while fixing two issues:

1. It no longer misclassifies normal inbound CDN/TLS return traffic to random client ports as a port scan.
2. It restores practical attack visibility for student/home-lab tests using Kali and Windows.

## Detection Sources

- TShark/Npcap live packet metadata across all selected interfaces
- Windows Defender Firewall log telemetry when enabled
- Normal activity classification for packet metadata that does not become an alert

## Critical / High / Normal Rules

### Critical / High

- TCP port scans and service discovery, MITRE T1046
- ARP host discovery and scan preparation, MITRE T1046
- Large inbound file transfers to the monitored Windows host, MITRE T1105
- Suspicious internal ports such as 4444/5555/6666/7777, MITRE T1021
- DNS tunneling-like long or high-entropy DNS queries, MITRE T1071.004
- Beaconing / C2-like repeated connections, MITRE T1071
- Unusual external connection ports, MITRE T1071

### Normal

- Browsing, DNS, HTTPS/TLS, QUIC, downloads, pings, and other packet metadata that is visible but does not cross a risk threshold.

## Recommended Kali Tests

```bash
sudo nmap -sS -Pn -p 1-65535 --max-retries 1 --min-rate 5000 192.168.4.165
sudo nmap -sV -O -Pn -p 135,2179,3000,7680,8501 192.168.4.165
```

## Large Inbound Transfer Test

On Kali:

```bash
mkdir -p ~/ndr-test
cd ~/ndr-test
dd if=/dev/zero of=large-test-file.bin bs=1M count=100
python3 -m http.server 8000
```

On Windows:

```powershell
curl http://192.168.4.189:8000/large-test-file.bin -OutFile large-test-file.bin
```

Expected detection: `Live Large Inbound File Transfer`.
