param(
    [string]$Interface = "all",
    [string]$Interfaces = "",
    [int]$ExfilThresholdMB = 50,
    [int]$PortScanPorts = 8,
    [int]$BeaconConnections = 8,
    [string]$TrustedIP = "192.168.4.1"
)

Write-Host "Starting real-time network monitor" -ForegroundColor Cyan
Write-Host "Keep this window open. Press Ctrl+C to stop." -ForegroundColor Yellow

if ($Interfaces -ne "") {
  python -m live_monitor.run_live_monitor `
    --interfaces $Interfaces `
    --trusted-ip $TrustedIP `
    --exfil-threshold-mb $ExfilThresholdMB `
    --min-portscan-ports $PortScanPorts `
    --min-beacon-connections $BeaconConnections
} else {
  python -m live_monitor.run_live_monitor `
    --interface $Interface `
    --trusted-ip $TrustedIP `
    --exfil-threshold-mb $ExfilThresholdMB `
    --min-portscan-ports $PortScanPorts `
    --min-beacon-connections $BeaconConnections
}
