from __future__ import annotations

import json
from dataclasses import dataclass, asdict
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Tuple

import numpy as np
import pandas as pd
import pyarrow.parquet as pq
import pyarrow as pa

from sklearn.impute import SimpleImputer
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
import joblib


DEFAULT_LABEL_COLUMN = "Label"

# You can add more if your split parquet still contains these
LEAKAGE_COLUMNS = {
    "Flow ID",
    "Source IP",
    "Destination IP",
    "Source Port",
    "Destination Port",
    "Timestamp",
    "timestamp",
}


@dataclass
class PreprocessManifest:
    created_at: str
    input_split_dir: str
    output_dir: str
    label_column: str
    rows_train: int
    rows_val: int
    rows_test: int
    feature_count: int
    feature_names: List[str]
    dropped_columns: List[str]
    notes: Dict[str, str]


def _load_parquet_to_df(path: Path, columns: List[str] | None = None) -> pd.DataFrame:
    # Uses pyarrow to read; pandas can be heavy for very wide data
    table = pq.read_table(path, columns=columns)
    return table.to_pandas()


def _get_numeric_feature_list(df: pd.DataFrame, label_col: str) -> List[str]:
    # Keep numeric columns only, exclude label + leakage cols
    cols = []
    for c in df.columns:
        if c == label_col:
            continue
        if c in LEAKAGE_COLUMNS:
            continue
        if pd.api.types.is_numeric_dtype(df[c]):
            cols.append(c)
    return cols


def _coerce_numeric(df: pd.DataFrame, feature_cols: List[str]) -> pd.DataFrame:
    # Ensure numeric dtype (float64) consistently
    out = df.copy()
    for c in feature_cols:
        out[c] = pd.to_numeric(out[c], errors="coerce")
    return out


def _replace_inf_with_nan(X: np.ndarray) -> np.ndarray:
    X = X.astype(np.float64, copy=False)
    X[~np.isfinite(X)] = np.nan
    return X


def build_feature_contract_and_transformer(
    split_dir: Path,
    output_dir: Path,
    label_column: str = DEFAULT_LABEL_COLUMN,
    batch_rows: int = 250_000,
) -> PreprocessManifest:
    """
    Reads train/val/test.parquet, determines a frozen numeric feature list from TRAIN,
    fits a train-only preprocessing pipeline, and saves transformed arrays + artifacts.
    """
    split_dir = Path(split_dir)
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    train_path = split_dir / "train.parquet"
    val_path = split_dir / "val.parquet"
    test_path = split_dir / "test.parquet"

    for p in [train_path, val_path, test_path]:
        if not p.exists():
            raise FileNotFoundError(f"Missing split file: {p}")

    # ---- 1) Determine feature list from a TRAIN sample (for speed) ----
    # Read first batch of train to infer numeric columns
    train_pf = pq.ParquetFile(train_path)
    first_batch = next(train_pf.iter_batches(batch_size=min(batch_rows, 200_000)))
    train_sample = first_batch.to_pandas()

    if label_column not in train_sample.columns:
        raise RuntimeError(f"Label column '{label_column}' not found in train.parquet")

    feature_cols = _get_numeric_feature_list(train_sample, label_column)
    if not feature_cols:
        raise RuntimeError("No numeric feature columns detected. Check dataset schema.")

    feature_cols = sorted(feature_cols)

    # ---- 2) Fit transformer on TRAIN only (streaming) ----
    # We do 2-pass streaming for stability:
    # Pass A: compute mean/std via partial sums (manual) OR use StandardScaler partial_fit.
    # sklearn StandardScaler supports partial_fit.
    imputer = SimpleImputer(strategy="median")
    scaler = StandardScaler(with_mean=True, with_std=True)

    # We'll fit imputer + scaler using incremental strategy:
    # - collect a sample reservoir for median imputation (median isn't incremental).
    # To keep it simple+quality, we do:
    #   (A) load train features into a memmap-like .npz in chunks (still big but manageable with np.savez not streaming)
    # Better: approximate median with sample.
    # Quality-first: use a reasonably large sample for medians, then fit scaler via partial_fit on fully imputed chunks.

    SAMPLE_TARGET = 500_000  # adjust if RAM limited
    sample_chunks = []
    sampled = 0

    for batch in train_pf.iter_batches(batch_size=batch_rows):
        df = batch.to_pandas()
        df = _coerce_numeric(df, feature_cols)
        X = df[feature_cols].to_numpy()
        X = _replace_inf_with_nan(X)

        # Reservoir-ish: just take slices until target reached
        if sampled < SAMPLE_TARGET:
            take = min(len(X), SAMPLE_TARGET - sampled)
            sample_chunks.append(X[:take])
            sampled += take

        if sampled >= SAMPLE_TARGET:
            break

    sample_X = np.vstack(sample_chunks) if sample_chunks else None
    if sample_X is None:
        raise RuntimeError("Unable to sample train features for imputer fit.")

    imputer.fit(sample_X)

    # Now fit scaler incrementally across all train data
    # using imputed chunks
    for batch in train_pf.iter_batches(batch_size=batch_rows):
        df = batch.to_pandas()
        df = _coerce_numeric(df, feature_cols)
        X = df[feature_cols].to_numpy()
        X = _replace_inf_with_nan(X)
        X = imputer.transform(X)
        scaler.partial_fit(X)

    transformer = Pipeline(steps=[
        ("imputer", imputer),
        ("scaler", scaler),
    ])

    # Save artifacts
    (output_dir / "feature_list.json").write_text(json.dumps(feature_cols, indent=2), encoding="utf-8")
    joblib.dump(transformer, output_dir / "transformer.joblib")

    # ---- 3) Transform train/val/test and save arrays ----
    def transform_split(parquet_path: Path, X_out: Path, y_out: Path) -> Tuple[int, Dict[str, int]]:
        pf = pq.ParquetFile(parquet_path)
        X_parts = []
        y_parts = []
        label_counts: Dict[str, int] = {}

        for batch in pf.iter_batches(batch_size=batch_rows):
            df = batch.to_pandas()

            if label_column not in df.columns:
                raise RuntimeError(f"Label column '{label_column}' missing in {parquet_path.name}")

            y = df[label_column].astype(str).to_numpy()
            for lab, cnt in pd.Series(y).value_counts().to_dict().items():
                label_counts[lab] = label_counts.get(lab, 0) + int(cnt)

            df = _coerce_numeric(df, feature_cols)
            X = df[feature_cols].to_numpy()
            X = _replace_inf_with_nan(X)
            X = transformer.transform(X)

            X_parts.append(X.astype(np.float32, copy=False))
            y_parts.append(y)

        X_full = np.vstack(X_parts) if X_parts else np.empty((0, len(feature_cols)), dtype=np.float32)
        y_full = np.concatenate(y_parts) if y_parts else np.empty((0,), dtype=object)

        # save
        np.savez_compressed(X_out, X=X_full)
        np.save(y_out, y_full, allow_pickle=True)

        return int(len(y_full)), label_counts

    n_train, lc_train = transform_split(train_path, output_dir / "X_train.npz", output_dir / "y_train.npy")
    n_val, lc_val = transform_split(val_path, output_dir / "X_val.npz", output_dir / "y_val.npy")
    n_test, lc_test = transform_split(test_path, output_dir / "X_test.npz", output_dir / "y_test.npy")

    dropped = sorted([c for c in train_sample.columns if c in LEAKAGE_COLUMNS and c != label_column])

    manifest = PreprocessManifest(
        created_at=datetime.utcnow().isoformat() + "Z",
        input_split_dir=str(split_dir.resolve()),
        output_dir=str(output_dir.resolve()),
        label_column=label_column,
        rows_train=n_train,
        rows_val=n_val,
        rows_test=n_test,
        feature_count=len(feature_cols),
        feature_names=feature_cols,
        dropped_columns=dropped,
        notes={
            "feature_policy": "numeric_only_from_train_schema",
            "imputer": "median (fit on 500k train sample)",
            "scaler": "StandardScaler (partial_fit over all train rows)",
            "leakage_columns_removed": "Flow ID / IPs / Ports / Timestamp (if present)",
        }
    )

    (output_dir / "preprocess_manifest.json").write_text(json.dumps(asdict(manifest), indent=2), encoding="utf-8")

    # Also store label counts per split for sanity
    (output_dir / "label_counts.json").write_text(json.dumps({
        "train": lc_train,
        "val": lc_val,
        "test": lc_test
    }, indent=2), encoding="utf-8")

    return manifest
