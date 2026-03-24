from __future__ import annotations

import json
import re
from dataclasses import dataclass, asdict
from datetime import datetime, UTC
from pathlib import Path
from typing import Dict, List, Tuple

import numpy as np
import pandas as pd
import pyarrow as pa
import pyarrow.parquet as pq


# Canonical labels used everywhere
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

def canonicalize_series(y: pd.Series) -> pd.Series:
    y = y.astype(str).map(_clean_label)
    def to_can(v: str) -> str:
        if v in RAW_TO_CANONICAL:
            return RAW_TO_CANONICAL[v]
        low = v.lower()
        if low.startswith("dos "):
            return "DoS"
        if "patator" in low:
            return "BruteForce"
        if low == "bot":
            return "Botnet"
        if "web" in low and "attack" in low:
            return "WebAttack"
        return v
    return y.map(to_can)


@dataclass
class SplitPlan:
    created_at: str
    strategy: str
    input_root: str
    output_root: str
    test_fraction: float
    val_fraction: float
    per_class_min_train: Dict[str, int]
    desired_counts: Dict[str, Dict[str, int]]
    realized_counts: Dict[str, Dict[str, int]]
    rows: Dict[str, int]
    notes: Dict[str, str]


def unify_schema(files: List[Path]) -> pa.Schema:
    fields: Dict[str, pa.DataType] = {}

    def promote(a: pa.DataType, b: pa.DataType) -> pa.DataType:
        if a == b:
            return a
        if pa.types.is_dictionary(a): a = pa.string()
        if pa.types.is_dictionary(b): b = pa.string()
        if pa.types.is_integer(a) and pa.types.is_integer(b): return pa.int64()
        if pa.types.is_floating(a) and pa.types.is_floating(b): return pa.float64()
        if (pa.types.is_integer(a) and pa.types.is_floating(b)) or (pa.types.is_floating(a) and pa.types.is_integer(b)):
            return pa.float64()
        return pa.string()

    for f in files:
        sch = pq.ParquetFile(f).schema_arrow
        for field in sch:
            name, dtype = field.name, field.type
            if pa.types.is_dictionary(dtype):
                dtype = pa.string()
            fields[name] = dtype if name not in fields else promote(fields[name], dtype)

    return pa.schema([pa.field(k, fields[k]) for k in sorted(fields.keys())])


def compute_totals(input_root: Path, label_col: str, batch_rows: int = 300_000) -> Dict[str, int]:
    totals = {c: 0 for c in CANONICAL_CLASSES}
    files = sorted(Path(input_root).rglob("*.parquet"))
    if not files:
        raise FileNotFoundError(f"No parquet files found under {input_root}")

    for f in files:
        pf = pq.ParquetFile(f)
        for batch in pf.iter_batches(batch_size=batch_rows, columns=[label_col]):
            df = batch.to_pandas()
            y = canonicalize_series(df[label_col])
            vc = y.value_counts()
            for k, v in vc.items():
                if k in totals:
                    totals[k] += int(v)

    return totals


def main():
    INPUT_ROOT = Path(r"C:\Users\naren\Downloads\PROJECTS\PROJECT_CHIMERA\agents\vigil\network_analysis\datasets\raw\_immutable\cicids2017_v1\extracted")
    OUT_SPLIT_DIR = Path(r"C:\Users\naren\Downloads\PROJECTS\PROJECT_CHIMERA\agents\vigil\network_analysis\datasets\processed\splits\cicids2017_v1_covsplit")
    OUT_SPLIT_DIR.mkdir(parents=True, exist_ok=True)

    LABEL_COL = "Label"
    SEED = 42
    rng = np.random.default_rng(SEED)

    # Fractions (row-level split)
    TEST_FRAC = 0.20
    VAL_FRAC = 0.15

    # Minimum training retention per class (important for rare classes)
    PER_CLASS_MIN_TRAIN = {
        "BENIGN": 50_000,
        "DDoS": 5_000,
        "DoS": 5_000,
        "PortScan": 2_000,
        "BruteForce": 2_000,
        "WebAttack": 200,
        "Botnet": 500,
        "Infiltration": 50,
        "Heartbleed": 10,
    }

    # ---- 1) Compute total counts per class ----
    totals = compute_totals(INPUT_ROOT, LABEL_COL)
    present = [c for c in CANONICAL_CLASSES if totals.get(c, 0) > 0]
    if len(present) < 2:
        raise RuntimeError(f"Dataset has too few canonical classes: {present}")

    # Clamp mins if dataset smaller than requested
    for c in CANONICAL_CLASSES:
        if totals.get(c, 0) == 0:
            PER_CLASS_MIN_TRAIN[c] = 0
        elif PER_CLASS_MIN_TRAIN.get(c, 0) > totals[c]:
            PER_CLASS_MIN_TRAIN[c] = max(1, totals[c] // 2)

    # Desired quotas per class
    desired_test = {}
    desired_val = {}
    desired_train = {}

    for c in CANONICAL_CLASSES:
        n = totals.get(c, 0)
        if n <= 0:
            desired_test[c] = desired_val[c] = desired_train[c] = 0
            continue

        t = int(round(n * TEST_FRAC))
        v = int(round(n * VAL_FRAC))
        tr = n - t - v

        # Enforce min train
        min_tr = PER_CLASS_MIN_TRAIN.get(c, 0)
        if tr < min_tr:
            deficit = min_tr - tr
            # reduce test first, then val
            reduce_t = min(deficit, t)
            t -= reduce_t
            deficit -= reduce_t
            reduce_v = min(deficit, v)
            v -= reduce_v
            deficit -= reduce_v
            tr = n - t - v

        # If still impossible (super rare), force all into train
        if tr < min_tr:
            t = 0
            v = 0
            tr = n

        desired_test[c] = t
        desired_val[c] = v
        desired_train[c] = tr

    # Remaining quotas while streaming
    rem_test = dict(desired_test)
    rem_val = dict(desired_val)

    realized = {
        "train": {c: 0 for c in CANONICAL_CLASSES},
        "val": {c: 0 for c in CANONICAL_CLASSES},
        "test": {c: 0 for c in CANONICAL_CLASSES},
    }

    # ---- 2) Prepare writers ----
    files = sorted(INPUT_ROOT.rglob("*.parquet"))
    schema = unify_schema(files)

    train_path = OUT_SPLIT_DIR / "train.parquet"
    val_path = OUT_SPLIT_DIR / "val.parquet"
    test_path = OUT_SPLIT_DIR / "test.parquet"
    for p in (train_path, val_path, test_path):
        if p.exists():
            p.unlink()

    w_train = pq.ParquetWriter(train_path, schema, compression="snappy")
    w_val = pq.ParquetWriter(val_path, schema, compression="snappy")
    w_test = pq.ParquetWriter(test_path, schema, compression="snappy")

    def write_df(writer: pq.ParquetWriter, df: pd.DataFrame):
        t = pa.Table.from_pandas(df, preserve_index=False)
        missing = [n for n in schema.names if n not in t.column_names]
        for col in missing:
            t = t.append_column(col, pa.nulls(t.num_rows, type=schema.field(col).type))
        t = t.select(schema.names).cast(schema, safe=False)
        writer.write_table(t)

    rows = {"train": 0, "val": 0, "test": 0}

    # ---- 3) Stream and allocate by per-class quotas ----
    for f in files:
        pf = pq.ParquetFile(f)
        for batch in pf.iter_batches(batch_size=250_000):
            df = batch.to_pandas()

            y_can = canonicalize_series(df[LABEL_COL])
            df[LABEL_COL] = y_can  # normalize label in output

            # build index lists per class for this batch
            idx_by_class: Dict[str, np.ndarray] = {}
            for c in CANONICAL_CLASSES:
                m = (y_can.values == c)
                if m.any():
                    idx_by_class[c] = np.where(m)[0]

            # assignment arrays: 0=train, 1=val, 2=test
            assign = np.zeros(len(df), dtype=np.int8)

            for c, idxs in idx_by_class.items():
                rng.shuffle(idxs)

                # allocate to test
                take_test = min(rem_test.get(c, 0), len(idxs))
                if take_test > 0:
                    assign[idxs[:take_test]] = 2
                    rem_test[c] -= take_test

                # allocate to val
                remaining_idxs = idxs[take_test:]
                take_val = min(rem_val.get(c, 0), len(remaining_idxs))
                if take_val > 0:
                    assign[remaining_idxs[:take_val]] = 1
                    rem_val[c] -= take_val

                # rest stays train (0)

            # write out
            if (assign == 2).any():
                df_test = df.loc[assign == 2]
                write_df(w_test, df_test)
                rows["test"] += len(df_test)
                vc = df_test[LABEL_COL].value_counts()
                for k, v in vc.items():
                    if k in realized["test"]:
                        realized["test"][k] += int(v)

            if (assign == 1).any():
                df_val = df.loc[assign == 1]
                write_df(w_val, df_val)
                rows["val"] += len(df_val)
                vc = df_val[LABEL_COL].value_counts()
                for k, v in vc.items():
                    if k in realized["val"]:
                        realized["val"][k] += int(v)

            if (assign == 0).any():
                df_tr = df.loc[assign == 0]
                write_df(w_train, df_tr)
                rows["train"] += len(df_tr)
                vc = df_tr[LABEL_COL].value_counts()
                for k, v in vc.items():
                    if k in realized["train"]:
                        realized["train"][k] += int(v)

    w_train.close(); w_val.close(); w_test.close()

    cov_train = sorted([c for c in CANONICAL_CLASSES if realized["train"][c] > 0])
    cov_test = sorted([c for c in CANONICAL_CLASSES if realized["test"][c] > 0])

    # Hard quality checks
    if "BENIGN" in cov_test and len(cov_test) == 1:
        raise RuntimeError("TEST ended up BENIGN-only. Reduce PER_CLASS_MIN_TRAIN or increase TEST_FRAC.")

    missing_in_train = sorted(list(set(cov_test) - set(cov_train)))
    if missing_in_train:
        raise RuntimeError(f"Invalid split: test contains labels missing in train: {missing_in_train}")

    plan = SplitPlan(
        created_at=datetime.now(UTC).isoformat(),
        strategy="row_level_stratified_quota",
        input_root=str(INPUT_ROOT.resolve()),
        output_root=str(OUT_SPLIT_DIR.resolve()),
        test_fraction=TEST_FRAC,
        val_fraction=VAL_FRAC,
        per_class_min_train=PER_CLASS_MIN_TRAIN,
        desired_counts={
            "train": desired_train,
            "val": desired_val,
            "test": desired_test,
            "totals": totals,
        },
        realized_counts=realized,
        rows=rows,
        notes={
            "why": "File-holdout is impossible here because each attack family is isolated to its own file. "
                   "This splitter makes TEST meaningful while guaranteeing test labels exist in TRAIN.",
        },
    )
    (OUT_SPLIT_DIR / "splits_manifest.json").write_text(json.dumps(asdict(plan), indent=2), encoding="utf-8")

    print("✅ Stratified quota split complete.")
    print("Rows:", rows)
    print("Train coverage:", cov_train)
    print("Test coverage:", cov_test)
    print("Output:", OUT_SPLIT_DIR)


if __name__ == "__main__":
    main()
