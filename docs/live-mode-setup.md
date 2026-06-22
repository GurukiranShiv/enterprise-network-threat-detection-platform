# Live Mode Setup

Live mode captures network metadata from your own Windows system using TShark and Npcap.

## 1. Install Wireshark

Install Wireshark and select:

- TShark command-line tool
- Npcap packet capture driver

Restart PowerShell after installation.

## 2. Check TShark

```powershell
tshark -v
```

## 3. List Interfaces

```powershell
python live_monitor/list_interfaces.py
```

## 4. Start Monitor

```powershell
python live_monitor/run_live_monitor.py --interface "Wi-Fi"
```

## 5. Start Dashboard

```powershell
streamlit run streamlit_app/app.py
```

## Troubleshooting

### TShark not found
Add Wireshark to PATH or reopen PowerShell.

### Permission denied / no packets
Run PowerShell as Administrator and confirm Npcap is installed.

### No alerts
This is normal during clean browsing. Alerts only appear when traffic crosses thresholds. Check the Live Packet Feed page to confirm packets are being captured.
