from __future__ import annotations

from live_monitor.network_utils import get_local_ips
from live_monitor.tshark_interface import list_interfaces


def main() -> None:
    print("\nLocal IP addresses detected on this host:")
    local_ips = sorted(get_local_ips())
    if local_ips:
        for ip in local_ips:
            print(f"  - {ip}")
    else:
        print("  No local IPs detected automatically.")

    print("\nTShark capture interfaces:")
    print(list_interfaces())
    print("Use the interface number or exact interface name in run_live_monitor.py")
    print('Example: python live_monitor/run_live_monitor.py --interface "Wi-Fi"')
    print('Example: python live_monitor/run_live_monitor.py --interface 5')


if __name__ == "__main__":
    main()
