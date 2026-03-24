from __future__ import annotations
"""
VIGIL - CICIDS2017 Step 3 Validator
Validates:
- Schema consistency
- Canonical label mapping coverage (100%)
- Missing / +/-inf detection
- Basic leakage sniff (column names)
- Numeric min/max tracking (for sanity / constant columns)

Designed to run on huge CSVs using chunked reading.
"""
import pyarrow.parquet as pq

import json
import math
import re
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple

import numpy as np
import pandas as pd


# ----------------------------
# Canonical mapping for CICIDS2017 (Option B multiclass)
# ----------------------------
RAW_TO_CANONICAL: Dict[str, str] = {
    "BENIGN": "BENIGN",
    "DDoS": "DDoS",
    "PortScan": "PortScan",
    "Bot": "Botnet",
    "Infiltration": "Infiltration",
    "Heartbleed": "Heartbleed",

    # DoS family
    "DoS Hulk": "DoS",
    "DoS GoldenEye": "DoS",
    "DoS slowloris": "DoS",
    "DoS Slowhttptest": "DoS",

    # Brute force family
    "FTP-Patator": "BruteForce",
    "SSH-Patator": "BruteForce",

    # Web attacks family (note: CIC uses an en dash in some exports)
    "Web Attack – Brute Force": "WebAttack",
    "Web Attack – XSS": "WebAttack",
    "Web Attack – Sql Injection": "WebAttack",
    "Web Attack - Brute Force": "WebAttack",
    "Web Attack - XSS": "WebAttack",
    "Web Attack - Sql Injection": "WebAttack",
}

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


# ----------------------------
# Config (you can edit safely)
# ----------------------------
DEFAULT_LABEL_COLUMN = "Label"
DEFAULT_DROP_COLUMNS = {"Flow ID", "Source IP", "Destination IP", "Timestamp"}

LEAKAGE_NAME_PATTERNS = [
    r"\blabel\b",
    r"\bclass\b",
    r"\bcategory\b",
    r"\battack\b",
    r"\bmalicious\b",
]


@dataclass
class FileReport:
    filename: str
    rows_seen: int
    columns: List[str]
    label_column_found: bool
    unmapped_labels: Dict[str, int]
    canonical_label_counts: Dict[str, int]
    missing_values_total: int
    inf_values_total: int
    numeric_min: Dict[str, float]
    numeric_max: Dict[str, float]
    suspected_leakage_columns: List[str]


@dataclass
class DatasetSummary:
    files_processed: int
    total_rows_seen: int
    all_columns_union: List[str]
    columns_mismatch_files: List[str]
    unmapped_labels_total: Dict[str, int]
    canonical_label_counts_total: Dict[str, int]
    missing_values_total: int
    inf_values_total: int
    suspected_leakage_columns_union: List[str]
    constant_numeric_columns: List[str]
    passed: bool
    failures: List[str]


def _safe_float(v) -> float:
    try:
        f = float(v)
        if math.isfinite(f):
            return f
        return f
    except Exception:
        return float("nan")


def _merge_counts(dst: Dict[str, int], src: Dict[str, int]) -> Dict[str, int]:
    for k, v in src.items():
        dst[k] = dst.get(k, 0) + int(v)
    return dst

def _clean_raw_label(s: str) -> str:
    """
    Normalize raw CICIDS labels across casing and broken dash encodings.

    Examples fixed:
      "Benign" -> "BENIGN"
      "Web Attack � XSS" -> "Web Attack - XSS"
      "Web Attack – XSS" -> "Web Attack - XSS"
    """
    if s is None:
        return ""
    s = str(s).strip()

    # Normalize benign casing
    if s.lower() == "benign":
        return "BENIGN"

    # Replace known bad dash / separator characters with normal hyphen
    # \ufffd is the replacement character �
    s = s.replace("\ufffd", "-")   # "Web Attack � XSS" -> "Web Attack - XSS"
    s = s.replace("–", "-")        # en dash -> hyphen
    s = s.replace("—", "-")        # em dash -> hyphen

    # Normalize common spacing patterns
    s = re.sub(r"\s*-\s*", " - ", s)     # ensure " - " spacing
    s = re.sub(r"\s+", " ", s).strip()  # collapse spaces

    return s


def _find_csv_files(root: Path) -> List[Path]:
    if root.is_file() and root.suffix.lower() == ".csv":
        return [root]
    if root.is_dir():
        return sorted([p for p in root.rglob("*.csv") if p.is_file()])
    raise FileNotFoundError(f"CSV path not found: {root}")


def _sniff_leakage_columns(columns: Iterable[str]) -> List[str]:
    suspects: List[str] = []
    joined_patterns = [re.compile(pat, flags=re.IGNORECASE) for pat in LEAKAGE_NAME_PATTERNS]
    for col in columns:
        for pat in joined_patterns:
            if pat.search(col):
                suspects.append(col)
                break
    # Don't flag the actual label column itself here; caller can remove it
    return sorted(set(suspects))


def validate_cicids2017(
    csv_root: Path,
    report_dir: Path,
    label_column: str = DEFAULT_LABEL_COLUMN,
    drop_columns: Optional[set] = None,
    chunksize: int = 200_000,
    max_files: Optional[int] = None,
) -> Tuple[DatasetSummary, List[FileReport]]:
    """
    Validate CICIDS2017 CSVs under csv_root and write reports into report_dir.

    chunksize: increase for speed, decrease for low RAM.
    max_files: for debugging; set None for full run.
    """
    csv_root = Path(csv_root)
    report_dir = Path(report_dir)
    report_dir.mkdir(parents=True, exist_ok=True)

    drop_columns = drop_columns or set(DEFAULT_DROP_COLUMNS)

    files = _find_csv_files(csv_root)
    if max_files is not None:
        files = files[:max_files]

    all_columns_union: set = set()
    first_file_columns: Optional[List[str]] = None
    columns_mismatch_files: List[str] = []

    unmapped_total: Dict[str, int] = {}
    canonical_total: Dict[str, int] = {c: 0 for c in CANONICAL_CLASSES}

    missing_total = 0
    inf_total = 0
    suspected_leakage_union: set = set()

    # Track global numeric min/max across dataset (helps detect constant columns)
    global_min: Dict[str, float] = {}
    global_max: Dict[str, float] = {}

    total_rows_seen = 0
    file_reports: List[FileReport] = []

    for fp in files:
        rows_seen = 0
        file_missing = 0
        file_inf = 0

        file_unmapped: Dict[str, int] = {}
        file_canonical: Dict[str, int] = {c: 0 for c in CANONICAL_CLASSES}

        file_min: Dict[str, float] = {}
        file_max: Dict[str, float] = {}

        # We sniff leakage based on header columns
        # For CICIDS2017, huge files: use iterator with chunks
        try:
            it = pd.read_csv(fp, chunksize=chunksize, low_memory=False)
        except Exception as e:
            # If encoding issues appear, try latin-1 fallback
            it = pd.read_csv(fp, chunksize=chunksize, low_memory=False, encoding="latin-1")

        file_columns: Optional[List[str]] = None
        label_column_found = False

        for chunk in it:
            if file_columns is None:
                file_columns = list(chunk.columns)
                all_columns_union.update(file_columns)

                if first_file_columns is None:
                    first_file_columns = file_columns
                elif file_columns != first_file_columns:
                    columns_mismatch_files.append(fp.name)

                suspects = _sniff_leakage_columns(file_columns)
                # We'll remove actual label column if it matches, later.
                suspected_leakage_union.update(suspects)

            rows_seen += int(len(chunk))
            total_rows_seen += int(len(chunk))

            if label_column in chunk.columns:
                label_column_found = True

                # Normalize label strings
                raw_labels = chunk[label_column].astype(str).map(_clean_raw_label)


                # Count raw labels
                raw_counts = raw_labels.value_counts(dropna=False).to_dict()

                # Map to canonical
                mapped = raw_labels.map(_map_to_canonical)
                unmapped_mask = mapped.isna()

                if unmapped_mask.any():
                    unmapped_series = raw_labels[unmapped_mask]
                    unmapped_counts = unmapped_series.value_counts().to_dict()
                    _merge_counts(file_unmapped, unmapped_counts)
                    _merge_counts(unmapped_total, unmapped_counts)

                # Count canonical labels
                mapped_counts = mapped.dropna().value_counts().to_dict()
                for k, v in mapped_counts.items():
                    if k in file_canonical:
                        file_canonical[k] += int(v)
                    else:
                        # If somehow a new canonical label appears, track it
                        file_canonical[k] = file_canonical.get(k, 0) + int(v)

                for k, v in mapped_counts.items():
                    canonical_total[k] = canonical_total.get(k, 0) + int(v)

            # Drop non-feature columns for numeric sanity checks
            feature_chunk = chunk.drop(columns=[c for c in drop_columns if c in chunk.columns], errors="ignore")

            # Missing values
            # Count across entire chunk (including label col if present—still useful)
            file_missing += int(feature_chunk.isna().sum().sum())

            # Inf values (numeric only)
            num_cols = feature_chunk.select_dtypes(include=[np.number]).columns
            if len(num_cols) > 0:
                num_vals = feature_chunk[num_cols].to_numpy(copy=False)
                # numpy.isinf expects floats; safe with numeric dtypes
                file_inf += int(np.isinf(num_vals).sum())

                # Update min/max trackers
                col_mins = np.nanmin(num_vals, axis=0)
                col_maxs = np.nanmax(num_vals, axis=0)

                for col, mn, mx in zip(num_cols, col_mins, col_maxs):
                    if not np.isfinite(mn):
                        continue
                    if col not in file_min:
                        file_min[col] = float(mn)
                        file_max[col] = float(mx)
                    else:
                        file_min[col] = float(min(file_min[col], mn))
                        file_max[col] = float(max(file_max[col], mx))

                    if col not in global_min:
                        global_min[col] = float(mn)
                        global_max[col] = float(mx)
                    else:
                        global_min[col] = float(min(global_min[col], mn))
                        global_max[col] = float(max(global_max[col], mx))

        missing_total += file_missing
        inf_total += file_inf

        suspected_cols = _sniff_leakage_columns(file_columns or [])
        # remove the known label column from suspects
        suspected_cols = [c for c in suspected_cols if c.lower() != label_column.lower()]

        file_reports.append(
            FileReport(
                filename=fp.name,
                rows_seen=rows_seen,
                columns=file_columns or [],
                label_column_found=label_column_found,
                unmapped_labels=file_unmapped,
                canonical_label_counts=file_canonical,
                missing_values_total=file_missing,
                inf_values_total=file_inf,
                numeric_min=file_min,
                numeric_max=file_max,
                suspected_leakage_columns=suspected_cols,
            )
        )

    # Derive constant columns (numeric): min == max across whole dataset
    constant_numeric_columns = []
    for col in global_min.keys():
        mn = global_min[col]
        mx = global_max[col]
        if np.isfinite(mn) and np.isfinite(mx) and mn == mx:
            constant_numeric_columns.append(col)
    constant_numeric_columns = sorted(constant_numeric_columns)

    # Determine pass/fail
    failures: List[str] = []
    if total_rows_seen == 0:
        failures.append("No rows were read from CSVs (check path).")

    # Unmapped labels should be zero for quality gate
    if sum(unmapped_total.values()) > 0:
        failures.append(f"Unmapped labels detected: {len(unmapped_total)} distinct raw labels not in mapping.")

    if missing_total > 0:
        failures.append(f"Missing values detected (total missing cells across numeric+non-numeric features): {missing_total}")

    if inf_total > 0:
        failures.append(f"Infinite values detected in numeric features: {inf_total}")

    # Label column must exist everywhere
    missing_label_files = [fr.filename for fr in file_reports if not fr.label_column_found]
    if missing_label_files:
        failures.append(f"Label column '{label_column}' not found in files: {missing_label_files[:5]}{'...' if len(missing_label_files) > 5 else ''}")

    # Column mismatch warning (not always fatal, but usually a problem)
    # We'll treat it as a failure for strict quality.
    if columns_mismatch_files:
        failures.append(f"Column schema mismatch across files (example files): {columns_mismatch_files[:5]}{'...' if len(columns_mismatch_files) > 5 else ''}")

    # Leakage suspects are warnings; not necessarily fatal but should be inspected.
    # We'll not fail on them automatically; we just report them.

    passed = len(failures) == 0

    summary = DatasetSummary(
        files_processed=len(file_reports),
        total_rows_seen=total_rows_seen,
        all_columns_union=sorted(all_columns_union),
        columns_mismatch_files=sorted(set(columns_mismatch_files)),
        unmapped_labels_total=dict(sorted(unmapped_total.items(), key=lambda x: -x[1])),
        canonical_label_counts_total=dict(sorted(canonical_total.items(), key=lambda x: CANONICAL_CLASSES.index(x[0]) if x[0] in CANONICAL_CLASSES else 999)),
        missing_values_total=missing_total,
        inf_values_total=inf_total,
        suspected_leakage_columns_union=sorted(set([c for c in suspected_leakage_union if c.lower() != label_column.lower()])),
        constant_numeric_columns=constant_numeric_columns,
        passed=passed,
        failures=failures,
    )

    # Write reports
    (report_dir / "schema_report.json").write_text(
        json.dumps(
            {
                "files_processed": summary.files_processed,
                "columns_union_count": len(summary.all_columns_union),
                "columns_union": summary.all_columns_union,
                "columns_mismatch_files": summary.columns_mismatch_files,
            },
            indent=2,
        ),
        encoding="utf-8",
    )

    (report_dir / "label_distribution.json").write_text(
        json.dumps(
            {
                "canonical_label_counts_total": summary.canonical_label_counts_total,
                "unmapped_labels_total": summary.unmapped_labels_total,
            },
            indent=2,
        ),
        encoding="utf-8",
    )

    (report_dir / "data_quality_report.json").write_text(
        json.dumps(
            {
                "total_rows_seen": summary.total_rows_seen,
                "missing_values_total": summary.missing_values_total,
                "inf_values_total": summary.inf_values_total,
                "constant_numeric_columns": summary.constant_numeric_columns,
                "suspected_leakage_columns_union": summary.suspected_leakage_columns_union,
            },
            indent=2,
        ),
        encoding="utf-8",
    )

    (report_dir / "file_reports.json").write_text(
        json.dumps([asdict(fr) for fr in file_reports], indent=2),
        encoding="utf-8",
    )

    summary_txt = []
    summary_txt.append("VIGIL CICIDS2017 - Step 3 Validation Summary")
    summary_txt.append("=" * 60)
    summary_txt.append(f"Files processed: {summary.files_processed}")
    summary_txt.append(f"Total rows seen: {summary.total_rows_seen}")
    summary_txt.append("")
    summary_txt.append("Canonical label counts:")
    for k in CANONICAL_CLASSES:
        summary_txt.append(f"  {k:14s} : {summary.canonical_label_counts_total.get(k, 0)}")
    summary_txt.append("")
    if summary.unmapped_labels_total:
        summary_txt.append("UNMAPPED raw labels (top):")
        for k, v in list(summary.unmapped_labels_total.items())[:20]:
            summary_txt.append(f"  {k} : {v}")
        summary_txt.append("")
    summary_txt.append(f"Missing values total: {summary.missing_values_total}")
    summary_txt.append(f"Infinite values total: {summary.inf_values_total}")
    summary_txt.append(f"Constant numeric columns: {len(summary.constant_numeric_columns)}")
    if summary.suspected_leakage_columns_union:
        summary_txt.append("")
        summary_txt.append("Suspected leakage columns (name-based sniff, inspect manually):")
        for c in summary.suspected_leakage_columns_union[:50]:
            summary_txt.append(f"  - {c}")
        if len(summary.suspected_leakage_columns_union) > 50:
            summary_txt.append("  ...")
    summary_txt.append("")
    summary_txt.append(f"PASSED: {summary.passed}")
    if summary.failures:
        summary_txt.append("FAILURES:")
        for f in summary.failures:
            summary_txt.append(f"  - {f}")

    (report_dir / "validation_summary.txt").write_text("\n".join(summary_txt), encoding="utf-8")

    return summary, file_reports

def _find_parquet_files(root: Path) -> List[Path]:
    root = Path(root)
    if root.is_file() and root.suffix.lower() == ".parquet":
        return [root]
    if root.is_dir():
        return sorted([p for p in root.rglob("*.parquet") if p.is_file()])
    raise FileNotFoundError(f"Parquet path not found: {root}")

def _clean_raw_label(s: str) -> str:
    """
    Normalize raw CICIDS labels across casing and broken encodings.
    Produces stable strings that are easy to map.
    """
    if s is None:
        return ""
    s = str(s).strip()

    # normalize common weird unicode replacement chars / dashes
    s = s.replace("\ufffd", "-")  # replacement char �
    s = s.replace("–", "-")       # en dash
    s = s.replace("—", "-")       # em dash

    # collapse whitespace
    s = re.sub(r"\s+", " ", s).strip()

    # Normalize "benign" variants
    if s.lower() == "benign":
        return "BENIGN"

    # Standardize "Web Attack" variants
    # Sometimes becomes: "Web Attack- XSS", "WebAttack - XSS", "Web Attack -Sql Injection", etc.
    if "web" in s.lower() and "attack" in s.lower():
        # normalize separators around '-'
        s = re.sub(r"\s*-\s*", " - ", s).strip()
        # normalize capitalization prefix
        # Keep suffix as-is for mapping
        if s.lower().startswith("web attack"):
            s = "Web Attack" + s[len("Web Attack"):]
        elif s.lower().startswith("webattack"):
            s = "Web Attack" + s[len("WebAttack"):]
        return s

    return s

def _map_to_canonical(clean_label: str) -> str | None:
    """
    Map a cleaned label to canonical class.
    Uses dict first, then safe pattern-based fallbacks for known CICIDS quirks.
    """
    if not clean_label:
        return None

    # exact mapping first
    if clean_label in RAW_TO_CANONICAL:
        return RAW_TO_CANONICAL[clean_label]

    low = clean_label.lower()

    # robust benign fallback
    if low == "benign":
        return "BENIGN"

    # robust web attack fallback
    # examples: "Web Attack - Sql Injection", "Web Attack - SQL Injection", "Web Attack - Sql-Injection"
    if "web attack" in low:
        if "xss" in low:
            return "WebAttack"
        if "sql" in low and "injection" in low:
            return "WebAttack"
        if "brute" in low and "force" in low:
            return "WebAttack"
        # Any other web-attack variants still map to WebAttack
        return "WebAttack"

    return None


def validate_cicids2017_parquet(
    parquet_root: Path,
    report_dir: Path,
    label_column: str = DEFAULT_LABEL_COLUMN,
    drop_columns: Optional[set] = None,
    chunksize_rows: int = 250_000,
    max_files: Optional[int] = None,
) -> Tuple[DatasetSummary, List[FileReport]]:
    """
    Parquet version of Step 3 validator.
    Reads parquet in row batches (via pyarrow) to avoid RAM blowups.
    """
    parquet_root = Path(parquet_root)
    report_dir = Path(report_dir)
    report_dir.mkdir(parents=True, exist_ok=True)

    drop_columns = drop_columns or set(DEFAULT_DROP_COLUMNS)

    files = _find_parquet_files(parquet_root)
    if max_files is not None:
        files = files[:max_files]

    all_columns_union: set = set()
    first_file_columns: Optional[List[str]] = None
    columns_mismatch_files: List[str] = []

    unmapped_total: Dict[str, int] = {}
    canonical_total: Dict[str, int] = {c: 0 for c in CANONICAL_CLASSES}

    missing_total = 0
    inf_total = 0
    suspected_leakage_union: set = set()

    global_min: Dict[str, float] = {}
    global_max: Dict[str, float] = {}

    total_rows_seen = 0
    file_reports: List[FileReport] = []

    for fp in files:
        rows_seen = 0
        file_missing = 0
        file_inf = 0

        file_unmapped: Dict[str, int] = {}
        file_canonical: Dict[str, int] = {c: 0 for c in CANONICAL_CLASSES}
        file_min: Dict[str, float] = {}
        file_max: Dict[str, float] = {}

        table = pq.ParquetFile(fp)
        schema_cols = [name for name in table.schema.names]
        all_columns_union.update(schema_cols)

        if first_file_columns is None:
            first_file_columns = schema_cols
        elif schema_cols != first_file_columns:
            columns_mismatch_files.append(fp.name)

        suspects = _sniff_leakage_columns(schema_cols)
        suspected_leakage_union.update(suspects)

        label_column_found = label_column in schema_cols
        suspected_cols = _sniff_leakage_columns(schema_cols)
        suspected_cols = [c for c in suspected_cols if c.lower() != label_column.lower()]

        # Read in row batches
        for batch in table.iter_batches(batch_size=chunksize_rows):
            chunk = batch.to_pandas()
            rows_seen += int(len(chunk))
            total_rows_seen += int(len(chunk))

            # Missing values
            # drop_columns only affects feature checks; missingness can be counted on features too
            feature_chunk = chunk.drop(columns=[c for c in drop_columns if c in chunk.columns], errors="ignore")
            file_missing += int(feature_chunk.isna().sum().sum())

            # Inf values on numerics
            num_cols = feature_chunk.select_dtypes(include=[np.number]).columns
            if len(num_cols) > 0:
                num_vals = feature_chunk[num_cols].to_numpy(copy=False)
                file_inf += int(np.isinf(num_vals).sum())

                col_mins = np.nanmin(num_vals, axis=0)
                col_maxs = np.nanmax(num_vals, axis=0)

                for col, mn, mx in zip(num_cols, col_mins, col_maxs):
                    if not np.isfinite(mn):
                        continue
                    if col not in file_min:
                        file_min[col] = float(mn)
                        file_max[col] = float(mx)
                    else:
                        file_min[col] = float(min(file_min[col], mn))
                        file_max[col] = float(max(file_max[col], mx))

                    if col not in global_min:
                        global_min[col] = float(mn)
                        global_max[col] = float(mx)
                    else:
                        global_min[col] = float(min(global_min[col], mn))
                        global_max[col] = float(max(global_max[col], mx))

            # Label mapping checks
            if label_column_found and label_column in chunk.columns:
                raw_labels = chunk[label_column].astype(str).map(_clean_raw_label)
                mapped = raw_labels.map(_map_to_canonical)
                unmapped_mask = mapped.isna()

                if unmapped_mask.any():
                    unmapped_series = raw_labels[unmapped_mask]
                    unmapped_counts = unmapped_series.value_counts().to_dict()
                    _merge_counts(file_unmapped, unmapped_counts)
                    _merge_counts(unmapped_total, unmapped_counts)

                mapped_counts = mapped.dropna().value_counts().to_dict()
                for k, v in mapped_counts.items():
                    file_canonical[k] = file_canonical.get(k, 0) + int(v)
                    canonical_total[k] = canonical_total.get(k, 0) + int(v)

        missing_total += file_missing
        inf_total += file_inf

        file_reports.append(
            FileReport(
                filename=fp.name,
                rows_seen=rows_seen,
                columns=schema_cols,
                label_column_found=label_column_found,
                unmapped_labels=file_unmapped,
                canonical_label_counts=file_canonical,
                missing_values_total=file_missing,
                inf_values_total=file_inf,
                numeric_min=file_min,
                numeric_max=file_max,
                suspected_leakage_columns=suspected_cols,
            )
        )

    constant_numeric_columns = []
    for col in global_min.keys():
        if np.isfinite(global_min[col]) and np.isfinite(global_max[col]) and global_min[col] == global_max[col]:
            constant_numeric_columns.append(col)
    constant_numeric_columns = sorted(constant_numeric_columns)

    failures: List[str] = []
    if total_rows_seen == 0:
        failures.append("No rows were read from parquet files (check path).")

    if sum(unmapped_total.values()) > 0:
        failures.append(f"Unmapped labels detected: {len(unmapped_total)} distinct raw labels not in mapping.")

    if missing_total > 0:
        failures.append(f"Missing values detected (total missing cells across features): {missing_total}")

    if inf_total > 0:
        failures.append(f"Infinite values detected in numeric features: {inf_total}")

    missing_label_files = [fr.filename for fr in file_reports if not fr.label_column_found]
    if missing_label_files:
        failures.append(f"Label column '{label_column}' not found in files: {missing_label_files[:5]}{'...' if len(missing_label_files) > 5 else ''}")

    if columns_mismatch_files:
        failures.append(f"Column schema mismatch across files (example files): {columns_mismatch_files[:5]}{'...' if len(columns_mismatch_files) > 5 else ''}")

    passed = len(failures) == 0

    summary = DatasetSummary(
        files_processed=len(file_reports),
        total_rows_seen=total_rows_seen,
        all_columns_union=sorted(all_columns_union),
        columns_mismatch_files=sorted(set(columns_mismatch_files)),
        unmapped_labels_total=dict(sorted(unmapped_total.items(), key=lambda x: -x[1])),
        canonical_label_counts_total=dict(sorted(canonical_total.items(), key=lambda x: CANONICAL_CLASSES.index(x[0]) if x[0] in CANONICAL_CLASSES else 999)),
        missing_values_total=missing_total,
        inf_values_total=inf_total,
        suspected_leakage_columns_union=sorted(set([c for c in suspected_leakage_union if c.lower() != label_column.lower()])),
        constant_numeric_columns=constant_numeric_columns,
        passed=passed,
        failures=failures,
    )

    # Write reports (same filenames as CSV version)
    (report_dir / "schema_report.json").write_text(
        json.dumps(
            {
                "files_processed": summary.files_processed,
                "columns_union_count": len(summary.all_columns_union),
                "columns_union": summary.all_columns_union,
                "columns_mismatch_files": summary.columns_mismatch_files,
            },
            indent=2,
        ),
        encoding="utf-8",
    )

    (report_dir / "label_distribution.json").write_text(
        json.dumps(
            {
                "canonical_label_counts_total": summary.canonical_label_counts_total,
                "unmapped_labels_total": summary.unmapped_labels_total,
            },
            indent=2,
        ),
        encoding="utf-8",
    )

    (report_dir / "data_quality_report.json").write_text(
        json.dumps(
            {
                "total_rows_seen": summary.total_rows_seen,
                "missing_values_total": summary.missing_values_total,
                "inf_values_total": summary.inf_values_total,
                "constant_numeric_columns": summary.constant_numeric_columns,
                "suspected_leakage_columns_union": summary.suspected_leakage_columns_union,
            },
            indent=2,
        ),
        encoding="utf-8",
    )

    (report_dir / "file_reports.json").write_text(
        json.dumps([asdict(fr) for fr in file_reports], indent=2),
        encoding="utf-8",
    )

    summary_txt = []
    summary_txt.append("VIGIL CICIDS2017 (PARQUET) - Step 3 Validation Summary")
    summary_txt.append("=" * 60)
    summary_txt.append(f"Files processed: {summary.files_processed}")
    summary_txt.append(f"Total rows seen: {summary.total_rows_seen}")
    summary_txt.append("")
    summary_txt.append("Canonical label counts:")
    for k in CANONICAL_CLASSES:
        summary_txt.append(f"  {k:14s} : {summary.canonical_label_counts_total.get(k, 0)}")
    summary_txt.append("")
    if summary.unmapped_labels_total:
        summary_txt.append("UNMAPPED raw labels (top):")
        for k, v in list(summary.unmapped_labels_total.items())[:20]:
            summary_txt.append(f"  {k} : {v}")
        summary_txt.append("")
    summary_txt.append(f"Missing values total: {summary.missing_values_total}")
    summary_txt.append(f"Infinite values total: {summary.inf_values_total}")
    summary_txt.append(f"Constant numeric columns: {len(summary.constant_numeric_columns)}")
    if summary.suspected_leakage_columns_union:
        summary_txt.append("")
        summary_txt.append("Suspected leakage columns (name-based sniff, inspect manually):")
        for c in summary.suspected_leakage_columns_union[:50]:
            summary_txt.append(f"  - {c}")
        if len(summary.suspected_leakage_columns_union) > 50:
            summary_txt.append("  ...")
    summary_txt.append("")
    summary_txt.append(f"PASSED: {summary.passed}")
    if summary.failures:
        summary_txt.append("FAILURES:")
        for f in summary.failures:
            summary_txt.append(f"  - {f}")

    (report_dir / "validation_summary.txt").write_text("\n".join(summary_txt), encoding="utf-8")

    return summary, file_reports
