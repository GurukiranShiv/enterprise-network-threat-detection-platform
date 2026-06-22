# Optional cleanup: run as Administrator to stop allowed/dropped firewall logging.
Set-NetFirewallProfile -Profile Domain,Public,Private -LogAllowed False -LogBlocked False
Write-Host "Windows Firewall allowed/blocked logging disabled." -ForegroundColor Yellow
