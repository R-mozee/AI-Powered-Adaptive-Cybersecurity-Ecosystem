from pathlib import Path
from split_builder import build_temporal_splits

if __name__ == "__main__":
    INPUT_ROOT = Path(r"C:\Users\naren\Downloads\PROJECTS\PROJECT_CHIMERA\agents\vigil\network_analysis\datasets\raw\_immutable\cicids2017_v1\extracted")

    OUTPUT_ROOT = Path(r"C:\Users\naren\Downloads\PROJECTS\PROJECT_CHIMERA\agents\vigil\network_analysis\datasets\processed\splits\cicids2017_v1")

    manifest = build_temporal_splits(
        parquet_root=INPUT_ROOT,
        output_root=OUTPUT_ROOT,
        label_column="Label",
        chunksize_rows=250_000,
        val_fraction_from_train=0.15,
        random_seed=42,
    )

    print("✅ Step 4 complete.")
    print("Strategy:", manifest.strategy)
    print("Timestamp column:", manifest.timestamp_column)
    print("Rows:", manifest.rows_total, "train:", manifest.rows_train, "val:", manifest.rows_val, "test:", manifest.rows_test)
    print("Outputs:", OUTPUT_ROOT)
