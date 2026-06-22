from __future__ import annotations

import csv
import shutil
import subprocess
import re
import time
from typing import Iterator, List, Sequence

from live_monitor.models import LivePacketEvent
from live_monitor.network_utils import infer_direction

# Keep this field list intentionally conservative for Windows/TShark compatibility.
# Some Wireshark versions silently fail on newer/renamed TLS/HTTP fields; these fields
# are stable and enough for live metadata, DNS, port, protocol, beaconing, and exfil logic.
FIELDS = [
    "frame.time_epoch",
    "_ws.col.Protocol",
    "ip.src",
    "ip.dst",
    "ipv6.src",
    "ipv6.dst",
    "arp.src.proto_ipv4",
    "arp.dst.proto_ipv4",
    "tcp.srcport",
    "tcp.dstport",
    "udp.srcport",
    "udp.dstport",
    "frame.len",
    "dns.qry.name",
    "http.host",
    "http.request.full_uri",
    "http.user_agent",
    "tls.handshake.extensions_server_name",
    "tcp.flags.syn",
    "tcp.flags.ack",
]


def require_tshark() -> str:
    exe = shutil.which("tshark")
    if not exe:
        # Common Windows default install locations. This makes the project work even
        # when Wireshark is installed but PATH was not refreshed correctly.
        candidates = [
            r"C:\Program Files\Wireshark\tshark.exe",
            r"C:\Program Files (x86)\Wireshark\tshark.exe",
            r"G:\Softwares\wireshark\tshark.exe",
            r"G:\Softwares\Wireshark\tshark.exe",
        ]
        for candidate in candidates:
            p = shutil.os.path.normpath(candidate)
            if shutil.os.path.exists(p):
                return p
        raise RuntimeError(
            "TShark was not found in PATH. Install Wireshark with TShark enabled, "
            "then reopen PowerShell. On Windows, also install Npcap when prompted."
        )
    return exe


def list_interfaces() -> str:
    exe = require_tshark()
    proc = subprocess.run([exe, "-D"], capture_output=True, text=True, check=False)
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr.strip() or "Failed to list TShark interfaces.")
    return proc.stdout


def parse_interface_numbers(raw: str, include_loopback: bool = False) -> list[str]:
    """Return capture interface numbers from `tshark -D` output.

    Windows does not have a single universal `any` interface, so the project
    expands --interface all into repeated -i arguments. ETW is excluded because
    it is not a normal packet interface. Loopback is excluded by default to avoid
    duplicate/noisy localhost traffic, but it can be included explicitly.
    """
    out: list[str] = []
    for line in raw.splitlines():
        m = re.match(r"^\s*(\d+)\.\s+(.+)$", line)
        if not m:
            continue
        num, desc = m.group(1), m.group(2).lower()
        if "etwdump" in desc or "event tracing" in desc:
            continue
        if not include_loopback and ("loopback" in desc or "npf_loopback" in desc):
            continue
        # Keep normal Npcap interfaces. This covers Wi-Fi, Ethernet, vEthernet,
        # VirtualBox/VMware adapters, Bluetooth PAN, and host-only adapters.
        if "\\device\\npf" in desc or "npf_" in desc:
            out.append(num)
    return out


def resolve_interfaces(interface: str | None = None, interfaces: str | None = None, include_loopback: bool = False) -> list[str]:
    if interfaces:
        return [x.strip() for x in interfaces.split(",") if x.strip()]
    if not interface:
        raise RuntimeError("Provide --interface, --interface all, or --interfaces 6,9,11.")
    if interface.strip().lower() == "all":
        nums = parse_interface_numbers(list_interfaces(), include_loopback=include_loopback)
        if not nums:
            raise RuntimeError("Could not resolve --interface all. Run python -m live_monitor.list_interfaces and choose interfaces manually.")
        return nums
    return [interface]


def build_tshark_command(interfaces: str | Sequence[str], capture_filter: str | None = None) -> List[str]:
    exe = require_tshark()
    if isinstance(interfaces, str):
        interface_list = [interfaces]
    else:
        interface_list = list(interfaces)
    cmd = [exe]
    for interface in interface_list:
        cmd.extend(["-i", str(interface)])
    cmd.extend([
        "-l",  # line buffered stdout
        "-n",  # no name resolution, faster and safer
        "-T",
        "fields",
        "-E",
        "header=n",
        "-E",
        "separator=\t",
        "-E",
        "occurrence=f",
    ])
    for field in FIELDS:
        cmd.extend(["-e", field])
    if capture_filter:
        cmd.extend(["-f", capture_filter])
    return cmd


def _to_int(value: str) -> int | None:
    try:
        return int(value)
    except Exception:
        return None


def _to_float(value: str) -> float:
    try:
        return float(value)
    except Exception:
        return time.time()


def _to_bool(value: str) -> bool:
    return str(value).strip() in {"1", "True", "true"}


def parse_tshark_line(line: str, local_ips: set[str], capture_interface: str = "") -> LivePacketEvent | None:
    # TShark field output is tab-separated. csv handles empty fields correctly.
    row = next(csv.reader([line.rstrip("\n")], delimiter="\t"), [])
    if len(row) < len(FIELDS):
        row.extend([""] * (len(FIELDS) - len(row)))

    (
        ts,
        protocol,
        ip_src,
        ip_dst,
        ipv6_src,
        ipv6_dst,
        arp_src,
        arp_dst,
        tcp_srcport,
        tcp_dstport,
        udp_srcport,
        udp_dstport,
        frame_len,
        dns_query,
        http_host,
        http_uri,
        http_user_agent,
        tls_sni,
        tcp_syn,
        tcp_ack,
    ) = row[: len(FIELDS)]

    src_ip = ip_src or ipv6_src or arp_src
    dst_ip = ip_dst or ipv6_dst or arp_dst
    if not src_ip or not dst_ip:
        return None

    src_port = _to_int(tcp_srcport or udp_srcport)
    dst_port = _to_int(tcp_dstport or udp_dstport)
    length = _to_int(frame_len) or 0
    proto = (protocol or "UNKNOWN").upper()

    return LivePacketEvent(
        timestamp=_to_float(ts),
        protocol=proto,
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        length=length,
        dns_query=dns_query.strip(),
        http_host=http_host.strip(),
        http_user_agent=http_user_agent.strip(),
        tls_sni=tls_sni.strip(),
        tcp_flags_syn=_to_bool(tcp_syn),
        tcp_flags_ack=_to_bool(tcp_ack),
        direction=infer_direction(src_ip, dst_ip, local_ips),
        capture_interface=capture_interface,
    )


def stream_events(interfaces: str | Sequence[str], local_ips: set[str], capture_filter: str | None = None) -> Iterator[LivePacketEvent]:
    cmd = build_tshark_command(interfaces, capture_filter)
    capture_label = ",".join(interfaces) if not isinstance(interfaces, str) else interfaces
    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1,
    )
    if proc.stdout is None:
        raise RuntimeError("Could not read TShark stdout.")

    lines_seen = 0
    try:
        for line in proc.stdout:
            lines_seen += 1
            event = parse_tshark_line(line, local_ips, capture_interface=capture_label)
            if event:
                yield event

        # If TShark exits quickly, surface its stderr instead of failing silently.
        rc = proc.poll()
        if rc not in (None, 0):
            err = ""
            if proc.stderr is not None:
                try:
                    err = proc.stderr.read().strip()
                except Exception:
                    err = ""
            raise RuntimeError(err or f"TShark exited with code {rc}.")
        if lines_seen == 0 and proc.poll() is not None:
            raise RuntimeError("TShark exited without producing packet metadata. Try another interface number.")
    finally:
        try:
            proc.terminate()
        except Exception:
            pass
