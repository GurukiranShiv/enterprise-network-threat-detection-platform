$ErrorActionPreference = "Stop"
$alertsPath = "data\alerts\live_alerts.json"
if (-not (Test-Path $alertsPath)) {
    Write-Host "No live alerts file found yet: $alertsPath"
    exit 0
}
$alerts = Get-Content $alertsPath -Raw | ConvertFrom-Json
if (-not $alerts) {
    Write-Host "No live alerts in current session."
    exit 0
}
$alerts | Select-Object timestamp,severity,risk_score,detection,source_ip,destination_ip,mitre_technique | Format-Table -AutoSize
