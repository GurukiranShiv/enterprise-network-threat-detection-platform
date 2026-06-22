# Use this if Npcap/TShark capture is not needed and you only want Windows host telemetry.
python -m hybrid_monitor.run_hybrid_monitor --no-packets --trusted-ip 192.168.4.1 --min-portscan-ports 5 --min-blocked-packets 20 --cooldown-seconds 120
