MITRE = {
    "Internal Port Scan": {
        "technique": "T1046 - Network Service Discovery",
        "tactic": "Discovery",
    },
    "SSH Brute Force": {
        "technique": "T1110 - Brute Force",
        "tactic": "Credential Access",
    },
    "Beaconing / C2-Like Traffic": {
        "technique": "T1071 - Application Layer Protocol",
        "tactic": "Command and Control",
    },
    "Suspicious DNS / Possible DNS Tunneling": {
        "technique": "T1071.004 - DNS",
        "tactic": "Command and Control",
    },
    "Suspicious Outbound Data Transfer": {
        "technique": "T1041 - Exfiltration Over C2 Channel",
        "tactic": "Exfiltration",
    },
    "Lateral Movement-Like Internal Communication": {
        "technique": "T1021 - Remote Services",
        "tactic": "Lateral Movement",
    },
    "Suricata IDS Alert": {
        "technique": "T1595 - Active Scanning / Multiple Techniques",
        "tactic": "Reconnaissance / Detection",
    },
}


def map_detection(detection_name: str):
    return MITRE.get(detection_name, {
        "technique": "T9999 - Custom Detection",
        "tactic": "Custom / Lab Detection",
    })
