param(
    [string]$Interfaces = "all",
    [string]$TrustedIP = "192.168.4.1"
)

$ProjectRoot = (Resolve-Path ".").Path
Write-Host "Opening multi-interface live monitor and dashboard..." -ForegroundColor Cyan

Start-Process powershell -ArgumentList "-NoExit", "-Command", "cd '$ProjectRoot'; .\.venv\Scripts\Activate.ps1; python -m live_monitor.run_live_monitor --interface $Interfaces --trusted-ip $TrustedIP"
Start-Sleep -Seconds 2
Start-Process powershell -ArgumentList "-NoExit", "-Command", "cd '$ProjectRoot'; .\.venv\Scripts\Activate.ps1; streamlit run streamlit_app/app.py"
