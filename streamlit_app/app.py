from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any, Dict, List

import pandas as pd
import streamlit as st

st.set_page_config(
    page_title="Live Network Threat Detection Platform",
    page_icon="🛡️",
    layout="wide",
)

PROJECT_ROOT = Path(__file__).resolve().parents[1]
LIVE_ALERTS_PATH = PROJECT_ROOT / "data" / "alerts" / "live_alerts.json"
DEMO_ALERTS_PATH = PROJECT_ROOT / "data" / "alerts" / "alerts.json"
STATUS_PATH = PROJECT_ROOT / "data" / "live" / "status.json"
LIVE_EVENTS_PATH = PROJECT_ROOT / "data" / "live" / "live_events.jsonl"


def load_json(path: Path, default: Any) -> Any:
    try:
        if not path.exists():
            return default
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return default


def load_alerts(path: Path) -> List[Dict[str, Any]]:
    data = load_json(path, [])
    return data if isinstance(data, list) else []


def read_recent_jsonl(path: Path, limit: int = 200) -> List[Dict[str, Any]]:
    if not path.exists():
        return []
    try:
        lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()[-limit:]
        rows = []
        for line in lines:
            try:
                rows.append(json.loads(line))
            except Exception:
                pass
        return rows
    except Exception:
        return []



def normal_activity_from_events(events: List[Dict[str, Any]]) -> pd.DataFrame:
    """Convert recent packet metadata into Normal observations for the UI.

    These are not incidents. They provide visibility into ordinary traffic such as
    DNS, HTTPS, QUIC, downloads, and browsing so the dashboard has all three views:
    Critical, High, and Normal.
    """
    rows = []
    for e in events:
        rows.append({
            "timestamp": e.get("timestamp", ""),
            "severity": "Normal",
            "activity": "Normal Live Packet Metadata",
            "source_ip": e.get("src_ip", ""),
            "destination_ip": e.get("dst_ip", ""),
            "protocol": e.get("protocol", ""),
            "src_port": e.get("src_port", ""),
            "dst_port": e.get("dst_port", ""),
            "length": e.get("length", 0),
            "dns_query": e.get("dns_query", ""),
            "direction": e.get("direction", ""),
            "telemetry_source": e.get("telemetry_source", e.get("capture_interface", "tshark_packet")),
            "firewall_action": e.get("firewall_action", ""),
            "capture_interface": e.get("capture_interface", ""),
            "analyst_note": "Observed and logged, but no suspicious threshold crossed.",
        })
    return pd.DataFrame(rows)


def show_normal_activity(events: List[Dict[str, Any]], limit: int = 100) -> None:
    normal_df = normal_activity_from_events(events[-limit:])
    if normal_df.empty:
        st.info("No normal packet metadata is visible yet. Keep the live monitor running and generate browsing/DNS traffic.")
        return
    st.dataframe(normal_df.sort_values("timestamp", ascending=False), use_container_width=True)

def severity_order(sev: str) -> int:
    return {"Critical": 3, "High": 2, "Normal": 1}.get(str(sev), 0)


def priority_order(priority: str) -> int:
    return {"P1": 4, "P2": 3, "P3": 2, "P4": 1}.get(str(priority), 0)


def ensure_alert_columns(df: pd.DataFrame) -> pd.DataFrame:
    defaults = {
        "alert_id": "",
        "timestamp": "",
        "detection": "Unknown",
        "severity": "Low",
        "risk_score": 0,
        "source_ip": "",
        "destination_ip": "",
        "mitre_technique": "",
        "mitre_tactic": "Unknown",
        "status": "Open",
        "analyst_verdict": "Needs Review",
        "confidence": "Medium",
        "triage_priority": "P3",
        "false_positive_considerations": "Review context before escalation.",
        "recommended_action": "Review event context and supporting telemetry.",
        "evidence": {},
    }
    for col, default in defaults.items():
        if col not in df.columns:
            df[col] = default
    df["risk_score"] = pd.to_numeric(df["risk_score"], errors="coerce").fillna(0).astype(int)
    df["severity_rank"] = df["severity"].apply(severity_order)
    df["priority_rank"] = df["triage_priority"].apply(priority_order)
    return df


def show_alert_summary(row: Dict[str, Any]) -> None:
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Severity", row.get("severity", ""))
    c2.metric("Risk Score", row.get("risk_score", 0))
    c3.metric("Priority", row.get("triage_priority", ""))
    c4.metric("Confidence", row.get("confidence", ""))

    st.markdown(f"### {row.get('detection', 'Unknown Detection')}")
    st.write(f"**Timestamp:** {row.get('timestamp', '')}")
    st.write(f"**Source:** `{row.get('source_ip', '')}`")
    st.write(f"**Destination:** `{row.get('destination_ip', '')}`")
    st.write(f"**MITRE Technique:** {row.get('mitre_technique', '')}")
    st.write(f"**MITRE Tactic:** {row.get('mitre_tactic', '')}")
    st.write(f"**Analyst Verdict:** `{row.get('analyst_verdict', 'Needs Review')}`")

    st.markdown("#### Why this alert fired")
    evidence = row.get("evidence", {}) if isinstance(row.get("evidence", {}), dict) else {}
    st.info(evidence.get("rule_reason", "The event matched one of the live detection rules."))

    st.markdown("#### Evidence")
    st.json(evidence)

    st.markdown("#### Recommended analyst action")
    st.success(row.get("recommended_action", "Review event context and supporting telemetry."))

    st.markdown("#### False-positive considerations")
    st.warning(row.get("false_positive_considerations", "Review local context before escalation."))

    st.markdown("#### Manual investigation checklist")
    src = row.get("source_ip", "")
    dst = row.get("destination_ip", "")
    st.code(
        f"""# Check active connections involving the source or destination
Get-NetTCPConnection | Where-Object {{$_.RemoteAddress -eq \"{dst}\" -or $_.LocalAddress -eq \"{src}\"}}

# Map network connections to processes
netstat -ano | findstr "{dst}"

# Check DNS resolution manually
nslookup {dst}

# If the source is your gateway/router or a known local device, mark as likely benign and add to trusted IPs.
""",
        language="powershell",
    )


st.title("Enterprise Network Threat Detection & Behavior Fingerprinting Platform")
st.caption("Live SOC-style dashboard for real-time TShark/Npcap traffic capture, production rolling-window detections, three-level severity triage, risk scoring, MITRE ATT&CK mapping, and analyst investigation.")

st.sidebar.header("Data Source")
source_choice = st.sidebar.radio(
    "Alert Mode",
    ["Live traffic alerts", "Saved/demo alerts"],
    index=0 if LIVE_ALERTS_PATH.exists() else 1,
)
alerts_path = LIVE_ALERTS_PATH if source_choice == "Live traffic alerts" else DEMO_ALERTS_PATH

st.sidebar.write("Alert File")
st.sidebar.code(str(alerts_path))

auto_refresh = st.sidebar.checkbox("Auto-refresh dashboard", value=source_choice == "Live traffic alerts")
refresh_seconds = st.sidebar.slider("Refresh interval seconds", min_value=2, max_value=15, value=3)

status = load_json(STATUS_PATH, {})
if source_choice == "Live traffic alerts":
    st.sidebar.markdown("---")
    st.sidebar.subheader("Live Monitor Status")
    if status.get("running"):
        st.sidebar.success("Live monitor running")
    elif status.get("error"):
        st.sidebar.error("Live monitor error")
        st.sidebar.caption(status.get("error"))
    else:
        st.sidebar.warning("Live monitor not running")
    st.sidebar.write(f"Packets seen: `{status.get('packets_seen', 0)}`")
    st.sidebar.write(f"Alerts seen: `{status.get('alerts_seen', 0)}`")
    if status.get("firewall_events_seen") is not None:
        st.sidebar.write(f"Firewall events: `{status.get('firewall_events_seen', 0)}`")
    if status.get("mode"):
        st.sidebar.caption(status.get("mode"))
    if status.get("interface"):
        st.sidebar.write(f"Interface: `{status.get('interface')}`")
    if status.get("trusted_ips"):
        st.sidebar.write("Trusted/suppressed IPs")
        st.sidebar.code("\n".join(status.get("trusted_ips", [])))
    if status.get("local_ips"):
        with st.sidebar.expander("Local IPs"):
            st.code("\n".join(status.get("local_ips", [])))

alerts = load_alerts(alerts_path)
df = ensure_alert_columns(pd.DataFrame(alerts)) if alerts else pd.DataFrame()
recent_events = read_recent_jsonl(LIVE_EVENTS_PATH, limit=500)
normal_df = normal_activity_from_events(recent_events)

page = st.sidebar.radio(
    "SOC View",
    [
        "Overview",
        "Severity Center",
        "Critical Alerts",
        "Normal Activity",
        "Live Packet Feed",
        "Incident Queue",
        "Incident Details",
        "Host Fingerprint",
        "Detection Logic",
        "How To Run Live",
    ],
)

if df.empty and page not in {"Live Packet Feed", "Normal Activity", "Severity Center", "How To Run Live", "Detection Logic"}:
    if source_choice == "Live traffic alerts":
        st.warning(
            "No live alerts yet. This is okay after tuning. Packet metadata can still be visible under Live Packet Feed. "
            "Alerts are now stricter and ignore router/multicast/local-discovery noise."
        )
    else:
        st.warning("No saved/demo alerts found.")

if page == "Overview":
    total = len(df)
    critical = int((df["severity"] == "Critical").sum()) if not df.empty else 0
    high = int((df["severity"] == "High").sum()) if not df.empty else 0
    normal = len(normal_df)
    avg_score = round(float(df["risk_score"].mean()), 1) if total else 0

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Critical", critical)
    c2.metric("High", high)
    c3.metric("Normal Observations", normal)
    c4.metric("Average Alert Risk", avg_score)

    st.subheader("Three-Level Severity Model")
    sev_counts = pd.Series({"Critical": critical, "High": high, "Normal": normal})
    st.bar_chart(sev_counts)

    if not df.empty:
        st.subheader("Alerts by Detection Type")
        st.bar_chart(df["detection"].value_counts())
        st.subheader("MITRE Tactics Observed")
        st.bar_chart(df["mitre_tactic"].value_counts())
        st.subheader("Top Risky Sources")
        src_counts = df.groupby("source_ip")["risk_score"].max().sort_values(ascending=False).head(10)
        st.bar_chart(src_counts)
    else:
        st.info("No Critical/High alerts yet. Normal observations are still being captured under Normal Activity / Live Packet Feed.")

    if source_choice == "Live traffic alerts":
        st.subheader("Current Live Runtime")
        c1, c2, c3 = st.columns(3)
        c1.metric("Packets Captured", status.get("packets_seen", 0))
        c2.metric("Live Alerts", status.get("alerts_seen", len(df)))
        c3.metric("Monitor Running", "Yes" if status.get("running") else "No")

elif page == "Severity Center":
    st.subheader("Critical / High / Normal Severity Center")
    c1, c2, c3 = st.columns(3)
    c1.metric("Critical", int((df["severity"] == "Critical").sum()) if not df.empty else 0)
    c2.metric("High", int((df["severity"] == "High").sum()) if not df.empty else 0)
    c3.metric("Normal", len(normal_df))
    if source_choice == "Live traffic alerts":
        st.caption(f"Hybrid sources: packets={status.get('packets_seen', 0)}, Windows firewall events={status.get('firewall_events_seen', 0)}")

    selected = st.radio("Show", ["Critical", "High", "Normal", "All"], horizontal=True)
    if selected in {"Critical", "High"}:
        view = df[df["severity"] == selected].copy() if not df.empty else pd.DataFrame()
        if view.empty:
            st.info(f"No {selected} alerts currently.")
        else:
            st.dataframe(view[[c for c in ["alert_id", "timestamp", "severity", "risk_score", "detection", "source_ip", "destination_ip", "mitre_technique", "analyst_verdict", "triage_priority", "telemetry_source"] if c in view.columns]].sort_values("timestamp", ascending=False), use_container_width=True)
    elif selected == "Normal":
        st.caption("Normal means packet metadata was observed but did not cross a suspicious threshold. This is visibility, not an incident.")
        show_normal_activity(recent_events, limit=150)
    else:
        st.markdown("#### Critical / High Alerts")
        if df.empty:
            st.info("No alerts currently.")
        else:
            sorted_alerts = df.sort_values(["severity_rank", "risk_score", "timestamp"], ascending=False).copy()
            display_cols = [c for c in ["alert_id", "timestamp", "severity", "risk_score", "detection", "source_ip", "destination_ip", "mitre_technique", "telemetry_source"] if c in sorted_alerts.columns]
            st.dataframe(sorted_alerts[display_cols], use_container_width=True)
        st.markdown("#### Recent Normal Observations")
        show_normal_activity(recent_events, limit=50)

elif page == "Normal Activity":
    st.subheader("Normal Activity")
    st.caption("Normal activity is real packet metadata captured from your system, but it is not suspicious enough to become an alert.")
    show_normal_activity(recent_events, limit=300)

elif page == "Critical Alerts":
    st.subheader("Critical / High Alert Triage")
    if df.empty:
        st.info("No alerts yet. After tuning, that can be a good sign during normal browsing.")
        st.stop()

    min_sev = st.selectbox("Show severity", ["Critical only", "Critical + High", "All"], index=1)
    if min_sev == "Critical only":
        view = df[df["severity"] == "Critical"].copy()
    elif min_sev == "Critical + High":
        view = df[df["severity"].isin(["Critical", "High"])].copy()
    else:
        view = df.copy()

    view = view.sort_values(["severity_rank", "risk_score", "timestamp"], ascending=False)
    if view.empty:
        st.success("No Critical/High alerts currently. Packet capture is still running; check Live Packet Feed for raw metadata.")
        st.stop()

    view_cols = [c for c in [
        "alert_id", "timestamp", "detection", "severity", "triage_priority", "risk_score",
        "source_ip", "destination_ip", "mitre_technique", "analyst_verdict", "confidence", "telemetry_source"
    ] if c in view.columns]
    st.dataframe(
        view[view_cols],
        width="stretch",
        hide_index=True,
    )

    st.markdown("---")
    selected = st.selectbox("Investigate alert", view["alert_id"].tolist())
    row = view[view["alert_id"] == selected].iloc[0].to_dict()
    show_alert_summary(row)

elif page == "Live Packet Feed":
    st.subheader("Recent Live Packet Metadata")
    events = read_recent_jsonl(LIVE_EVENTS_PATH, limit=250)
    if not events:
        st.info("No live packet metadata found yet. Start live_monitor/run_live_monitor.py and keep it running.")
    else:
        edf = pd.DataFrame(events)
        display_cols = [
            c for c in [
                "timestamp", "telemetry_source", "firewall_action", "capture_interface", "direction", "protocol", "src_ip", "src_port", "dst_ip", "dst_port", "length", "dns_query", "tls_sni", "http_host"
            ] if c in edf.columns
        ]
        st.dataframe(edf[display_cols].tail(120), width="stretch", hide_index=True)
        st.caption("This is packet metadata only. HTTPS payload contents are not decrypted or displayed.")

elif page == "Incident Queue":
    if df.empty:
        st.stop()
    st.subheader("Risk-Based Incident Queue")

    c1, c2, c3 = st.columns(3)
    sev_filter = c1.multiselect("Severity", ["Critical", "High", "Normal"], default=["Critical", "High"])
    det_filter = c2.multiselect("Detection", sorted(df["detection"].unique().tolist()), default=[])
    min_score = c3.slider("Minimum risk score", 0, 100, 50)

    queue = df.copy()
    if sev_filter:
        queue = queue[queue["severity"].isin(sev_filter)]
    if det_filter:
        queue = queue[queue["detection"].isin(det_filter)]
    queue = queue[queue["risk_score"] >= min_score]
    queue = queue.sort_values(["severity_rank", "risk_score", "timestamp"], ascending=False)

    queue_cols = [c for c in [
        "alert_id", "timestamp", "detection", "severity", "triage_priority", "risk_score",
        "source_ip", "destination_ip", "mitre_technique", "analyst_verdict", "status", "telemetry_source"
    ] if c in queue.columns]
    st.dataframe(
        queue[queue_cols],
        width="stretch",
        hide_index=True,
    )

elif page == "Incident Details":
    if df.empty:
        st.stop()
    st.subheader("Incident Investigation View")
    sorted_df = df.sort_values(["severity_rank", "risk_score", "timestamp"], ascending=False)
    selected = st.selectbox("Select Alert", sorted_df["alert_id"].tolist())
    row = sorted_df[sorted_df["alert_id"] == selected].iloc[0].to_dict()
    show_alert_summary(row)

elif page == "Host Fingerprint":
    if df.empty:
        st.stop()
    st.subheader("Host Behavior Fingerprint")
    hosts = sorted(set(df["source_ip"].dropna().astype(str).tolist()))
    host = st.selectbox("Select source host", hosts)
    hdf = df[df["source_ip"] == host]

    c1, c2, c3 = st.columns(3)
    c1.metric("Alerts", len(hdf))
    c2.metric("Max Risk", int(hdf["risk_score"].max()) if not hdf.empty else 0)
    c3.metric("Unique Detections", hdf["detection"].nunique())

    st.markdown("#### Detection Mix")
    st.bar_chart(hdf["detection"].value_counts())

    st.markdown("#### Host Alerts")
    st.dataframe(
        hdf[[c for c in ["alert_id", "detection", "severity", "risk_score", "destination_ip", "mitre_technique", "analyst_verdict", "telemetry_source"] if c in hdf.columns]],
        width="stretch",
        hide_index=True,
    )

elif page == "Detection Logic":
    st.subheader("Hybrid NDR Detection Engineering Notes")
    st.markdown("""
    The live mode does not wait for a finished sample log file. TShark streams packet metadata into Python, and the detector evaluates rolling time windows while traffic is still being captured.

    **Important tuning change:** the detector still captures all packet metadata, but it suppresses common background traffic from becoming incidents. This includes gateway chatter, multicast, link-local, mDNS, SSDP, LLMNR, common web/DNS/NTP ports, and tiny ACK/keepalive noise.

    | Live Detection | Core Logic | ATT&CK Mapping | Tuning |
    |---|---|---|---|
    | Live Port Scan / Service Discovery | Same source touches many uncommon destination ports within 60 seconds | T1046 | Suppresses gateway, multicast, local discovery, and common ports |
    | Live Beaconing / C2-Like Traffic | Repeated outbound connections at stable intervals | T1071 | Requires 8+ repeated connections and stable timing |
    | Live Suspicious DNS | Long, deep, or high-entropy DNS queries | T1071.004 | Higher thresholds to avoid ordinary CDN domains |
    | Live Suspicious Outbound Transfer | High outbound byte volume to external destination | T1041 | Ignores private/gateway/multicast destinations |
    | Live Lateral Movement-Like Communication | Internal host touches multiple peers/admin ports | T1021 | Suppresses gateway and requires admin-service patterns |
    | Live Unusual External Port | Outbound traffic to uncommon external port | T1071 | Ignores common ports and local discovery noise |
    | Windows Firewall Port Scan / Blocked Probe Pattern | Many blocked/allowed connection attempts against the Windows host | T1046 | Detects scans even when Npcap sees only ARP or partial VM-to-host traffic |
    """)

    st.markdown("#### Why false positives are expected")
    st.write(
        "Real laptops constantly generate background traffic from Windows services, browsers, cloud sync, DNS, mDNS, IPv6 discovery, updates, and router communication. A strong detection project should not hide this; it should capture it as telemetry and tune alerting so only higher-risk patterns become incidents."
    )

elif page == "How To Run Live":
    st.subheader("Run Real-Time Monitoring")
    st.markdown("1. Install **Wireshark** and include **TShark**. During install, also install **Npcap**.")
    st.markdown("2. Open **PowerShell as Administrator** in the project folder.")
    st.code("python -m venv .venv\n.\\.venv\\Scripts\\Activate.ps1\npip install -r requirements.txt", language="powershell")
    st.markdown("3. Confirm TShark and list interfaces.")
    st.code("tshark -v\npython -m live_monitor.list_interfaces", language="powershell")
    st.markdown("4. Enable Windows Firewall logging so host-targeted scans are visible even if packet capture misses VM-to-host TCP probes.")
    st.code(r".\scripts\enable_windows_firewall_logging.ps1", language="powershell")
    st.markdown("5. Start the hybrid monitor. This combines TShark/Npcap packets and Windows Firewall host telemetry.")
    st.code("python -m hybrid_monitor.run_hybrid_monitor --interface all --trusted-ip 192.168.4.1 --min-portscan-ports 5 --min-blocked-packets 20", language="powershell")
    st.markdown("6. Open another PowerShell terminal for the dashboard.")
    st.code(".\\.venv\\Scripts\\Activate.ps1\nstreamlit run streamlit_app/app.py", language="powershell")
    st.markdown("7. Normal browsing should populate packet metadata. Alerts appear only when behavior crosses tuned thresholds.")

if auto_refresh:
    time.sleep(refresh_seconds)
    st.rerun()
