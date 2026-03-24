from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Dict, List, Tuple

import pandas as pd
import pyarrow.parquet as pq


CANONICAL_CLASSES = [
    "BENIGN",
    "DDoS",
    "DoS",
    "PortScan",
    "BruteForce",
    "WebAttack",
    "Botnet",
    "Infiltration",
    "Heartbleed",
]

RAW_TO_CANONICAL = {
    "BENIGN": "BENIGN",
    "DDoS": "DDoS",
    "PortScan": "PortScan",
    "Bot": "Botnet",
    "Botnet": "Botnet",
    "Infiltration": "Infiltration",
    "Heartbleed": "Heartbleed",

    "DoS Hulk": "DoS",
    "DoS GoldenEye": "DoS",
    "DoS slowloris": "DoS",
    "DoS Slowhttptest": "DoS",

    "FTP-Patator": "BruteForce",
    "SSH-Patator": "BruteForce",

    "Web Attack - Brute Force": "WebAttack",
    "Web Attack - XSS": "WebAttack",
    "Web Attack - Sql Injection": "WebAttack",
    "Web Attack – Brute Force": "WebAttack",
    "Web Attack – XSS": "WebAttack",
    "Web Attack – Sql Injection": "WebAttack",
}

def _clean_label(s: str) -> str:
    s = str(s).strip()

    if s.lower() == "benign":
        return "BENIGN"

    s = s.replace("\ufffd", "-")
    s = s.replace("–", "-")
    s = s.replace("—", "-")
    s = re.sub(r"\s+", " ", s).strip()
    s = re.sub(r"\s*-\s*", " - ", s).strip()

    low = s.lower()
    if "web" in low and "attack" in low:
        if "xss" in low:
            return "Web Attack - XSS"
        if "sql" in low and "injection" in low:
            return "Web Attack - Sql Injection"
        if "brute" in low and "force" in low:
            return "Web Attack - Brute Force"
        return "WebAttack"

    return s

def canonicalize_one(label: str) -> str:
    label = _clean_label(label)
    if label in RAW_TO_CANONICAL:
        return RAW_TO_CANONICAL[label]

    low = label.lower()
    if low.startswith("dos "):
        return "DoS"
    if "patator" in low:
        return "BruteForce"
    if low == "bot":
        return "Botnet"
    if "web" in low and "attack" in low:
        return "WebAttack"

    return label  # unknown

def index_file_labels(
    parquet_root: Path,
    label_column: str = "Label",
    batch_rows: int = 300_000,
) -> Tuple[List[Dict], Dict[str, int]]:
    parquet_root = Path(parquet_root)
    files = sorted(parquet_root.rglob("*.parquet"))
    if not files:
        raise FileNotFoundError(f"No parquet files found under: {parquet_root}")

    per_file: List[Dict] = []
    dataset_total: Dict[str, int] = {}

    for f in files:
        pf = pq.ParquetFile(f)
        if label_column not in pf.schema.names:
            raise RuntimeError(f"Label column '{label_column}' not found in: {f.name}")

        rows = 0
        counts: Dict[str, int] = {}
        canonical_counts: Dict[str, int] = {}

        for batch in pf.iter_batches(batch_size=batch_rows, columns=[label_column]):
            df = batch.to_pandas()
            y = df[label_column].astype(str).map(canonicalize_one)

            vc = y.value_counts().to_dict()
            for k, v in vc.items():
                counts[k] = counts.get(k, 0) + int(v)
                dataset_total[k] = dataset_total.get(k, 0) + int(v)
                if k in CANONICAL_CLASSES:
                    canonical_counts[k] = canonical_counts.get(k, 0) + int(v)

            rows += len(df)

        per_file.append({
            "file": str(f),
            "name": f.name,
            "rows": rows,
            "label_counts_canonical": canonical_counts,
            "canonical_present": sorted([c for c in CANONICAL_CLASSES if canonical_counts.get(c, 0) > 0]),
        })

    return per_file, dataset_total


def save_index(per_file: List[Dict], dataset_total: Dict[str, int], out_path: Path) -> None:
    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "per_file": per_file,
        "dataset_total": dataset_total,
    }
    out_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
