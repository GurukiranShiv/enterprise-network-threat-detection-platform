from pathlib import Path
from typing import List, Dict
import csv


def read_tsv(path: Path) -> List[Dict[str, str]]:
    if not path.exists():
        return []
    rows = []
    with path.open("r", encoding="utf-8") as f:
        reader = csv.DictReader(f, delimiter="\t")
        for row in reader:
            rows.append({k: (v if v is not None else "") for k, v in row.items()})
    return rows


def load_zeek_logs(input_dir: str) -> Dict[str, List[Dict[str, str]]]:
    base = Path(input_dir)
    return {
        "conn": read_tsv(base / "zeek_conn.log"),
        "dns": read_tsv(base / "zeek_dns.log"),
        "http": read_tsv(base / "zeek_http.log"),
    }
