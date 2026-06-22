# Hybrid NDR Mode

Hybrid mode combines network packet metadata and Windows host telemetry.

## Why hybrid mode exists

During testing with Kali inside VirtualBox on the same Windows laptop, TShark on the Windows Wi-Fi adapter may only see ARP, not all TCP probes. This is a packet visibility limitation caused by VM-to-host traffic pathing, not a dashboard issue.

To solve this, the project reads Windows Defender Firewall logs. If Nmap sends many probes and Windows drops them, the firewall log provides the missing evidence.

## Data sources

- TShark/Npcap: IPs, ports, protocol, packet length, DNS query when visible, TCP SYN/ACK flags.
- Windows Defender Firewall log: ALLOW/DROP, protocol, source/destination IP, ports, TCP flags.

## Detection examples

- T1046 Network Service Discovery from many destination ports or many blocked probes.
- T1071 unusual external port or beaconing behavior.
- T1071.004 suspicious DNS.
- T1041 suspicious outbound data volume.
- T1021 lateral movement-like internal admin-port traffic.
