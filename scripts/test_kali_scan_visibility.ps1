param(
    [Parameter(Mandatory=$true)]
    [string]$KaliIP
)
$env:Path = "C:\Program Files\Wireshark;" + $env:Path
Write-Host "Watching packet visibility for Kali IP: $KaliIP" -ForegroundColor Cyan
Write-Host "Run nmap from Kali while this is running." -ForegroundColor Yellow
tshark -i 6 -f "host $KaliIP or arp" -T fields -e frame.time_relative -e eth.src -e ip.src -e tcp.srcport -e ip.dst -e tcp.dstport -e tcp.flags -e _ws.col.Info
