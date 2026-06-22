from detection_engine.utils import severity_from_score


def clamp(value: int, minimum: int = 1, maximum: int = 100) -> int:
    return max(minimum, min(maximum, int(value)))


def score_port_scan(unique_ports: int, suricata_confirmed: bool = False) -> int:
    score = 35 + min(unique_ports, 60)
    if suricata_confirmed:
        score += 15
    return clamp(score)


def score_bruteforce(failed_attempts: int, unique_usernames: int = 1) -> int:
    return clamp(35 + failed_attempts * 3 + unique_usernames * 5)


def score_beaconing(connection_count: int, avg_interval: float, interval_stddev: float) -> int:
    regularity_bonus = max(0, int(25 - interval_stddev))
    count_bonus = min(25, connection_count * 3)
    return clamp(35 + regularity_bonus + count_bonus)


def score_dns(query_length: int, entropy: float, subdomain_depth: int) -> int:
    return clamp(25 + (query_length // 4) + int(entropy * 7) + subdomain_depth * 4)


def score_exfil(bytes_out: int, unusual_destination: bool = True) -> int:
    mb = bytes_out / (1024 * 1024)
    score = 40 + int(min(35, mb * 10))
    if unusual_destination:
        score += 15
    return clamp(score)


def score_lateral(unique_destinations: int, admin_ports: int) -> int:
    return clamp(40 + unique_destinations * 10 + admin_ports * 8)


def severity(score: int) -> str:
    return severity_from_score(score)
