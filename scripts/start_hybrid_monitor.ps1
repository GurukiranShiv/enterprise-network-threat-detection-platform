# Run as Administrator from the project root.
$env:Path = "C:\Program Files\Wireshark;" + $env:Path
python -m hybrid_monitor.run_hybrid_monitor --interface all --trusted-ip 192.168.4.1 --min-portscan-ports 5 --min-blocked-packets 20 --cooldown-seconds 120
