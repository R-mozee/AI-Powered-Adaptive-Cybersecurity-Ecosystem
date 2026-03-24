from pathlib import Path
from data_validator import validate_cicids2017_parquet

if __name__ == "__main__":
    # ✅ CHANGE THIS to your actual parquet folder
    DATA_ROOT = Path(r"C:\Users\naren\Downloads\PROJECTS\PROJECT_CHIMERA\agents\vigil\network_analysis\datasets\raw\_immutable\cicids2017_v1\extracted")

    REPORT_DIR = Path(r"C:\Users\naren\Downloads\PROJECTS\PROJECT_CHIMERA\agents\vigil\network_analysis\datasets\processed\reports\cicids2017")

    summary, _ = validate_cicids2017_parquet(
        parquet_root=DATA_ROOT,
        report_dir=REPORT_DIR,
        label_column="Label",          # if your parquet uses 'label', change this
        chunksize_rows=250_000,        # tune if RAM issues
        max_files=None,               # set 1 to test quickly
    )

    print("\nDone.")
    print(f"PASSED: {summary.passed}")
    print(f"Reports written to: {REPORT_DIR.resolve()}")
    if not summary.passed:
        print("\nFailures:")
        for f in summary.failures:
            print(" -", f)
