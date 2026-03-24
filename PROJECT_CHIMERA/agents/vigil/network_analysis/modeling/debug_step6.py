from pathlib import Path
import numpy as np
import joblib
from collections import Counter

LABELS = [
    "BENIGN","DDoS","DoS","PortScan","BruteForce","WebAttack","Botnet","Infiltration","Heartbleed"
]

def load_npz_X(path: Path):
    return np.load(path)["X"]

def main():
    FEATURES_DIR = Path(r"C:\Users\naren\Downloads\PROJECTS\PROJECT_CHIMERA\agents\vigil\network_analysis\datasets\processed\features\cicids2017_v1")
    BASELINE_DIR = FEATURES_DIR / "baseline_lr"

    y_train = np.load(FEATURES_DIR / "y_train.npy", allow_pickle=True).astype(str)
    y_val   = np.load(FEATURES_DIR / "y_val.npy", allow_pickle=True).astype(str)
    y_test  = np.load(FEATURES_DIR / "y_test.npy", allow_pickle=True).astype(str)

    def summarize(name, y):
        c = Counter(y)
        present = sorted([k for k in c.keys() if k in LABELS])
        print(f"\n{name} rows={len(y)} unique={len(c)}")
        print("present labels:", present)
        for k in present:
            print(f"  {k:12s} {c[k]}")
        return set(present)

    tr = summarize("TRAIN", y_train)
    va = summarize("VAL", y_val)
    te = summarize("TEST", y_test)

    print("\nCoverage checks:")
    print("TEST labels missing in TRAIN:", sorted(list(te - tr)))
    print("TRAIN labels missing in TEST:", sorted(list(tr - te)))

    # If model exists, show predictions distribution
    model_path = BASELINE_DIR / "model.joblib"
    if model_path.exists():
        model = joblib.load(model_path)
        X_test = load_npz_X(FEATURES_DIR / "X_test.npz")
        y_pred = model.predict(X_test)
        cp = Counter(y_pred)
        print("\nPREDICTIONS on TEST:")
        for k, v in cp.most_common():
            print(f"  {k:12s} {v}")

if __name__ == "__main__":
    main()
