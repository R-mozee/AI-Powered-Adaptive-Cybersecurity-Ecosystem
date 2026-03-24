from pathlib import Path
from feature_contract import build_feature_contract_and_transformer

if __name__ == "__main__":
    SPLIT_DIR = Path(r"C:\Users\naren\Downloads\PROJECTS\PROJECT_CHIMERA\agents\vigil\network_analysis\datasets\processed\splits\cicids2017_v1_covsplit")
    OUTPUT_DIR = Path(r"C:\Users\naren\Downloads\PROJECTS\PROJECT_CHIMERA\agents\vigil\network_analysis\datasets\processed\features\cicids2017_v1_covsplit")

    manifest = build_feature_contract_and_transformer(
        split_dir=SPLIT_DIR,
        output_dir=OUTPUT_DIR,
        label_column="Label",
        batch_rows=250_000,
    )

    print("✅ Step 5 complete.")
    print("Rows:", manifest.rows_train, manifest.rows_val, manifest.rows_test)
    print("Feature count:", manifest.feature_count)
    print("Artifacts:", OUTPUT_DIR)
