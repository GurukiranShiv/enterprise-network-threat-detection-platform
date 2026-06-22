# Run this in PowerShell as Administrator.
# Enables Windows Defender Firewall logging so host-targeted scans are visible even when packet capture misses VM-to-host TCP probes.

$LogDir = "$env:SystemRoot\System32\LogFiles\Firewall"
$LogFile = "$LogDir\pfirewall.log"

New-Item -ItemType Directory -Path $LogDir -Force | Out-Null

Set-NetFirewallProfile -Profile Domain,Public,Private `
  -LogAllowed True `
  -LogBlocked True `
  -LogMaxSizeKilobytes 32768 `
  -LogFileName $LogFile

Write-Host "Windows Firewall logging enabled." -ForegroundColor Green
Write-Host "Log file: $LogFile" -ForegroundColor Cyan
Get-NetFirewallProfile | Select-Object Name,Enabled,LogAllowed,LogBlocked,LogFileName,LogMaxSizeKilobytes | Format-Table -AutoSize
