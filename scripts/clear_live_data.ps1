New-Item -ItemType Directory -Path data\alerts -Force | Out-Null
New-Item -ItemType Directory -Path data\live -Force | Out-Null
Set-Content -Path data\alerts\live_alerts.json -Value "[]"
Set-Content -Path data\live\live_events.jsonl -Value ""
@'
{
  "running": false,
  "mode": "Hybrid NDR: packet + Windows host telemetry",
  "packets_seen": 0,
  "firewall_events_seen": 0,
  "alerts_seen": 0,
  "message": "Live data cleared. Start monitoring with python -m hybrid_monitor.run_hybrid_monitor --interface all."
}
'@ | Set-Content -Path data\live\status.json
Write-Host "Cleared live alerts, live telemetry events, and status." -ForegroundColor Green
