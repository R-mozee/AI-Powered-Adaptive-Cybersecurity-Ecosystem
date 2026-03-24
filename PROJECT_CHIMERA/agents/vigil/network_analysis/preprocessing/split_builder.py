from __future__ import annotations

import json
import re
from dataclasses import dataclass, asdict
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import numpy as np
import pandas as pd
import pyarrow.parquet as pq
import pyarrow as pa


# ---------- Config you may tweak ----------
DEFAULT_LABEL_COLUMN = "Label"
DEFAULT_DROP_COLUMNS = {"Flow ID", "Source IP", "Destination IP"}  # keep Timestamp if present
DEFAULT_TIMESTAMP_CANDIDATES = ["Timestamp", "timestamp", "Time", "time", "datetime", "DateTime"]

# Validation: keep these canonical classes
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


@dataclass
class SplitManifest:
    created_at: str
    input_root: str
    output_root: str
    strategy: str
    timestamp_column: Optional[str]
    files_used: List[str]
    rules: Dict[str, str]
    rows_total: int
    rows_train: int
    rows_val: int
    rows_test: int
    label_counts_train: Dict[str, int]
    label_counts_val: Dict[str, int]
    label_counts_test: Dict[str, int]


def _find_parquet_files(root: Path) -> List[Path]:
    root = Path(root)
    if root.is_file() and root.suffix.lower() == ".parquet":
        return [root]
    if root.is_dir():
        return sorted([p for p in root.rglob("*.parquet") if p.is_file()])
    raise FileNotFoundError(f"Parquet path not found: {root}")


def _detect_timestamp_column(sample_file: Path, candidates: List[str]) -> Optional[str]:
    pf = pq.ParquetFile(sample_file)
    cols = set(pf.schema.names)
    for c in candidates:
        if c in cols:
            return c
    # also try case-insensitive match
    lower_map = {x.lower(): x for x in pf.schema.names}
    for c in candidates:
        if c.lower() in lower_map:
            return lower_map[c.lower()]
    return None

def _unify_arrow_schema(files: List[Path]) -> pa.Schema:
    """
    Create a stable schema that can hold all file schemas.
    Strategy:
      - If a field appears with different int widths, promote to int64.
      - If float widths differ, promote to float64.
      - If types conflict (int vs float), promote to float64.
      - Keep dictionary string labels as plain string to avoid dict mismatch edge cases.
    """
    # Start with empty
    fields: Dict[str, pa.DataType] = {}

    def promote(a: pa.DataType, b: pa.DataType) -> pa.DataType:
        if a == b:
            return a

        # Dictionary -> string (common for Label)
        if pa.types.is_dictionary(a) and pa.types.is_string(a.value_type):
            a = pa.string()
        if pa.types.is_dictionary(b) and pa.types.is_string(b.value_type):
            b = pa.string()

        # int promotions
        if pa.types.is_integer(a) and pa.types.is_integer(b):
            return pa.int64()

        # float promotions
        if pa.types.is_floating(a) and pa.types.is_floating(b):
            return pa.float64()

        # int + float -> float64
        if (pa.types.is_integer(a) and pa.types.is_floating(b)) or (pa.types.is_floating(a) and pa.types.is_integer(b)):
            return pa.float64()

        # timestamp conflicts -> timestamp[ns]
        if pa.types.is_timestamp(a) and pa.types.is_timestamp(b):
            return pa.timestamp("ns")

        # fallback: string (safest)
        return pa.string()

    # Merge schemas
    for f in files:
        pf = pq.ParquetFile(f)
        sch = pf.schema_arrow
        for field in sch:
            name = field.name
            dtype = field.type
            if name not in fields:
                # dictionary label -> string
                if pa.types.is_dictionary(dtype) and pa.types.is_string(dtype.value_type):
                    dtype = pa.string()
                fields[name] = dtype
            else:
                fields[name] = promote(fields[name], dtype)

    # Keep deterministic order: sort by name
    unified = pa.schema([pa.field(k, fields[k]) for k in sorted(fields.keys())])
    return unified


def _safe_parse_datetime(series: pd.Series) -> pd.Series:
    """
    Robust datetime parsing. CIC timestamps sometimes look like:
      "07/07/2017 02:30:00 PM"
    or ISO. We try pandas inference.
    """
    # errors='coerce' will produce NaT for unparsable
    dt = pd.to_datetime(series, errors="coerce", infer_datetime_format=True)
    return dt


def _weekday_name(dt: pd.Timestamp) -> str:
    # Monday=0 ... Sunday=6
    return ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"][dt.weekday()]


def _count_labels(df: pd.DataFrame, label_col: str) -> Dict[str, int]:
    if label_col not in df.columns:
        return {}
    vc = df[label_col].astype(str).value_counts().to_dict()
    # Ensure stable ordering keys
    out = {k: int(vc.get(k, 0)) for k in CANONICAL_CLASSES if k in vc}
    # add any unknown labels if present
    for k, v in vc.items():
        if k not in out:
            out[k] = int(v)
    return out


def build_temporal_splits(
    parquet_root: Path,
    output_root: Path,
    label_column: str = DEFAULT_LABEL_COLUMN,
    timestamp_candidates: List[str] = DEFAULT_TIMESTAMP_CANDIDATES,
    chunksize_rows: int = 250_000,
    val_fraction_from_train: float = 0.15,
    random_seed: int = 42,
) -> SplitManifest:
    """
    Creates:
      - test = all Friday rows (if timestamp exists) OR all Friday files (filename strategy)
      - train/val = remaining rows split by sampling (val_fraction_from_train)
    Writes: train.parquet, val.parquet, test.parquet, splits_manifest.json
    """
    parquet_root = Path(parquet_root)
    output_root = Path(output_root)
    output_root.mkdir(parents=True, exist_ok=True)

    files = _find_parquet_files(parquet_root)
    unified_schema = _unify_arrow_schema(files)
    if not files:
        raise FileNotFoundError("No parquet files found.")

    ts_col = _detect_timestamp_column(files[0], timestamp_candidates)

    # Writers
    train_path = output_root / "train.parquet"
    val_path = output_root / "val.parquet"
    test_path = output_root / "test.parquet"

    # remove existing outputs to avoid appending mixed runs
    for p in [train_path, val_path, test_path]:
        if p.exists():
            p.unlink()

    train_writer = None
    val_writer = None
    test_writer = None

    rng = np.random.default_rng(random_seed)

    strategy = ""
    rules = {}

    # If no timestamp, decide file-based split
    friday_files = []
    non_friday_files = []
    if ts_col is None:
        strategy = "filename_based"
        rules = {
            "test": "All files whose filename contains 'Friday' (case-insensitive) go to test.",
            "train_val": "All other files go to train/val; val is sampled from train_val rows.",
        }
        for f in files:
            if re.search(r"friday", f.name, flags=re.IGNORECASE):
                friday_files.append(f)
            else:
                non_friday_files.append(f)

        if not friday_files:
            raise RuntimeError(
                "No timestamp column found AND no files with 'Friday' in filename. "
                "Cannot construct Friday-only test."
            )
    else:
        strategy = "timestamp_based"
        rules = {
            "test": "Rows whose parsed timestamp weekday == Friday go to test.",
            "train_val": f"All other weekdays go to train/val; val is sampled {val_fraction_from_train:.0%} from train_val rows.",
        }

    total_rows = 0
    total_train = 0
    total_val = 0
    total_test = 0

    # For label counts, we will aggregate by reading back small counts incrementally
    label_counts_train: Dict[str, int] = {}
    label_counts_val: Dict[str, int] = {}
    label_counts_test: Dict[str, int] = {}

    def _write_table(writer_ref, df: pd.DataFrame, path: Path):
        nonlocal train_writer, val_writer, test_writer

        # Convert to arrow
        table = pa.Table.from_pandas(df, preserve_index=False)

        # Cast columns to unified schema + add missing columns if any
        # 1) Add missing columns
        missing_cols = [name for name in unified_schema.names if name not in table.column_names]
        if missing_cols:
            for col in missing_cols:
                table = table.append_column(col, pa.nulls(table.num_rows, type=unified_schema.field(col).type))

        # 2) Reorder columns
        table = table.select(unified_schema.names)

        # 3) Cast types
        table = table.cast(unified_schema, safe=False)

        if writer_ref is None:
            writer_ref = pq.ParquetWriter(path, unified_schema, compression="snappy")

        writer_ref.write_table(table)
        return writer_ref

    # Process files
    for f in (friday_files + non_friday_files) if ts_col is None else files:
        pf = pq.ParquetFile(f)

        for batch in pf.iter_batches(batch_size=chunksize_rows):
            df = batch.to_pandas()
            total_rows += len(df)

            # Drop obvious leakage columns but keep Timestamp for splitting if present
            drop_cols = [c for c in DEFAULT_DROP_COLUMNS if c in df.columns]
            if drop_cols:
                df = df.drop(columns=drop_cols, errors="ignore")

            if label_column in df.columns:
                # Keep only known labels if desired; for now, allow all but report counts.
                pass

            if ts_col is None:
                # file-based: entire file goes to test if it's a friday file
                if re.search(r"friday", f.name, flags=re.IGNORECASE):
                    test_writer = _write_table(test_writer, df, test_path)
                    total_test += len(df)
                    c = _count_labels(df, label_column)
                    for k, v in c.items():
                        label_counts_test[k] = label_counts_test.get(k, 0) + v
                else:
                    # sample val rows from this chunk; rest train
                    mask_val = rng.random(len(df)) < val_fraction_from_train
                    df_val = df[mask_val]
                    df_train = df[~mask_val]

                    if len(df_train) > 0:
                        train_writer = _write_table(train_writer, df_train, train_path)
                        total_train += len(df_train)
                        c = _count_labels(df_train, label_column)
                        for k, v in c.items():
                            label_counts_train[k] = label_counts_train.get(k, 0) + v

                    if len(df_val) > 0:
                        val_writer = _write_table(val_writer, df_val, val_path)
                        total_val += len(df_val)
                        c = _count_labels(df_val, label_column)
                        for k, v in c.items():
                            label_counts_val[k] = label_counts_val.get(k, 0) + v
            else:
                # timestamp-based
                dt = _safe_parse_datetime(df[ts_col])
                # If too many NaT, stop—timestamp split is unreliable
                nat_rate = float(dt.isna().mean())
                if nat_rate > 0.01:
                    raise RuntimeError(
                        f"Timestamp parse failed for >1% rows in a chunk. "
                        f"nat_rate={nat_rate:.3f}. Column={ts_col}. File={f.name}"
                    )

                weekday = dt.dt.weekday  # Monday=0 ... Sunday=6
                is_friday = weekday == 4

                df_test = df[is_friday]
                df_trainval = df[~is_friday]

                if len(df_test) > 0:
                    test_writer = _write_table(test_writer, df_test, test_path)
                    total_test += len(df_test)
                    c = _count_labels(df_test, label_column)
                    for k, v in c.items():
                        label_counts_test[k] = label_counts_test.get(k, 0) + v

                if len(df_trainval) > 0:
                    mask_val = rng.random(len(df_trainval)) < val_fraction_from_train
                    df_val = df_trainval[mask_val]
                    df_train = df_trainval[~mask_val]

                    if len(df_train) > 0:
                        train_writer = _write_table(train_writer, df_train, train_path)
                        total_train += len(df_train)
                        c = _count_labels(df_train, label_column)
                        for k, v in c.items():
                            label_counts_train[k] = label_counts_train.get(k, 0) + v

                    if len(df_val) > 0:
                        val_writer = _write_table(val_writer, df_val, val_path)
                        total_val += len(df_val)
                        c = _count_labels(df_val, label_column)
                        for k, v in c.items():
                            label_counts_val[k] = label_counts_val.get(k, 0) + v

    # Close writers
    for w in [train_writer, val_writer, test_writer]:
        if w is not None:
            w.close()

    if total_test == 0:
        raise RuntimeError("Test split ended up empty. Friday split failed (no Friday rows/files found).")

    manifest = SplitManifest(
        created_at=datetime.utcnow().isoformat() + "Z",
        input_root=str(parquet_root.resolve()),
        output_root=str(output_root.resolve()),
        strategy=strategy,
        timestamp_column=ts_col,
        files_used=[str(p.name) for p in files],
        rules=rules,
        rows_total=int(total_rows),
        rows_train=int(total_train),
        rows_val=int(total_val),
        rows_test=int(total_test),
        label_counts_train=label_counts_train,
        label_counts_val=label_counts_val,
        label_counts_test=label_counts_test,
    )

    (output_root / "splits_manifest.json").write_text(json.dumps(asdict(manifest), indent=2), encoding="utf-8")
    return manifest
