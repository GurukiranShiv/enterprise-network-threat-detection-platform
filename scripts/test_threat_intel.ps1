Write-Host "Testing local threat-intel detection. These are safe demo domains/IPs from config\threat_intel.json."
Write-Host "1) DNS query match"
nslookup malicious.test
Write-Host "2) HTTP Host header match over plain HTTP. This may fail to connect, but the HTTP metadata can still be visible if a server exists."
try { curl http://malicious.test -UseBasicParsing } catch { Write-Host "HTTP request failed; DNS alert may still be generated." }
Write-Host "3) Malicious IP ping test. ICMP has no HTTP header; this tests IP-based detection if packets leave the host."
ping 203.0.113.66 -n 2
