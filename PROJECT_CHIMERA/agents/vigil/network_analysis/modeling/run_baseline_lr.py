from __future__ import annotations

from pathlib import Path
import json
from collections import Counter
import re

import numpy as np
import joblib

from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import GridSearchCV, PredefinedSplit
from sklearn.multiclass import OneVsRestClassifier

from evaluate_utils import make_eval_report, save_eval_report


# Canonical classes in fixed order (match your Step 1/3 contract)
LABELS = [
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

# Map known CICIDS raw labels -> canonical
RAW_TO_CANONICAL = {
    "BENIGN": "BENIGN",
    "DDoS": "DDoS",
    "PortScan": "PortScan",
    "Bot": "Botnet",
    "Botnet": "Botnet",
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

    # Web attacks family (dash variants)
    "Web Attack - Brute Force": "WebAttack",
    "Web Attack - XSS": "WebAttack",
    "Web Attack - Sql Injection": "WebAttack",
    "Web Attack – Brute Force": "WebAttack",
    "Web Attack – XSS": "WebAttack",
    "Web Attack – Sql Injection": "WebAttack",
}


def load_npz_X(path: Path) -> np.ndarray:
    return np.load(path, allow_pickle=False)["X"]


def _clean_label(s: str) -> str:
    """
    Normalize raw strings so mapping works across encoding/casing quirks.
    """
    s = str(s).strip()

    # Fix benign casing
    if s.lower() == "benign":
        return "BENIGN"

    # Fix unicode replacement char and dash variants
    s = s.replace("\ufffd", "-")  # �
    s = s.replace("–", "-")
    s = s.replace("—", "-")
    s = re.sub(r"\s+", " ", s).strip()
    s = re.sub(r"\s*-\s*", " - ", s).strip()

    # Normalize WebAttack-like labels into standard keys
    low = s.lower()
    if "web" in low and "attack" in low:
        # Convert "WebAttacks" -> "Web Attack" if present
        if low.startswith("webattacks"):
            s = "Web Attack" + s[len("WebAttacks"):]
        elif low.startswith("webattack"):
            s = "Web Attack" + s[len("WebAttack"):]
        elif low.startswith("web attack"):
            # keep
            pass

        # If it contains known subtypes, standardize
        if "xss" in low:
            return "Web Attack - XSS"
        if "sql" in low and "injection" in low:
            return "Web Attack - Sql Injection"
        if "brute" in low and "force" in low:
            return "Web Attack - Brute Force"
        # unknown web-attack subtype -> still WebAttack
        return "WebAttack"

    return s


def canonicalize_labels(y: np.ndarray) -> np.ndarray:
    """
    Converts raw labels in y_* into canonical labels.
    Unknowns remain as-is so we can report them.
    """
    y = y.astype(str)
    y = np.array([_clean_label(v) for v in y], dtype=object)

    out = []
    for v in y:
        if v in RAW_TO_CANONICAL:
            out.append(RAW_TO_CANONICAL[v])
        else:
            # fallback patterns
            low = str(v).lower()

            if low.startswith("dos "):
                out.append("DoS")
            elif low in ("ftp-patator", "ssh-patator"):
                out.append("BruteForce")
            elif "patator" in low:
                out.append("BruteForce")
            elif low == "bot":
                out.append("Botnet")
            elif "web" in low and "attack" in low:
                out.append("WebAttack")
            else:
                out.append(v)  # keep unknown for diagnostics

    return np.array(out, dtype=object)


def filter_to_canonical(X: np.ndarray, y: np.ndarray, split_name: str) -> tuple[np.ndarray, np.ndarray]:
    """
    Keep only canonical labels, but after canonicalization.
    """
    y_can = canonicalize_labels(y)
    mask = np.isin(y_can, LABELS)

    unknown = Counter(y_can[~mask])
    kept = int(mask.sum())
    dropped = len(y_can) - kept

    if kept == 0:
        raise ValueError(
            f"[{split_name}] 0 samples match canonical labels after canonicalization.\n"
            f"Unknown labels (top 20): {unknown.most_common(20)}"
        )

    if dropped > 0:
        print(f"⚠ [{split_name}] Dropped {dropped} rows with truly unknown labels. Top:", unknown.most_common(8))

    return X[mask], y_can[mask]


def main():
    FEATURES_DIR = Path(
        r"C:\Users\naren\Downloads\PROJECTS\PROJECT_CHIMERA\agents\vigil\network_analysis\datasets\processed\features\cicids2017_v1_covsplit"
    )

    X_train = load_npz_X(FEATURES_DIR / "X_train.npz")
    y_train = np.load(FEATURES_DIR / "y_train.npy", allow_pickle=True)

    X_val = load_npz_X(FEATURES_DIR / "X_val.npz")
    y_val = np.load(FEATURES_DIR / "y_val.npy", allow_pickle=True)

    X_test = load_npz_X(FEATURES_DIR / "X_test.npz")
    y_test = np.load(FEATURES_DIR / "y_test.npy", allow_pickle=True)

    # Canonicalize + filter (should drop ~0 now)
    X_train, y_train = filter_to_canonical(X_train, y_train, "TRAIN")
    X_val, y_val = filter_to_canonical(X_val, y_val, "VAL")
    X_test, y_test = filter_to_canonical(X_test, y_test, "TEST")

    print("\nLabel coverage after canonicalization:")
    print("TRAIN:", sorted(set(y_train)))
    print("VAL  :", sorted(set(y_val)))
    print("TEST :", sorted(set(y_test)))

    # One-vs-rest Logistic Regression (no deprecated multi_class)
    base_lr = LogisticRegression(
        solver="saga",
        max_iter=12000,
        n_jobs=-1,
        class_weight="balanced",
    )
    base = OneVsRestClassifier(base_lr, n_jobs=-1)

    param_grid = {
        "estimator__C": [0.05, 0.1, 0.5, 1.0, 2.0],
        "estimator__penalty": ["l2"],
    }

    X_tv = np.vstack([X_train, X_val])
    y_tv = np.concatenate([y_train, y_val])

    test_fold = np.concatenate([
        -1 * np.ones(len(y_train), dtype=int),
        0 * np.ones(len(y_val), dtype=int),
    ])
    ps = PredefinedSplit(test_fold=test_fold)

    grid = GridSearchCV(
        estimator=base,
        param_grid=param_grid,
        scoring="f1_macro",
        cv=ps,
        n_jobs=-1,
        verbose=1,
    )

    grid.fit(X_tv, y_tv)
    best_model = grid.best_estimator_

    print("\nBest params:", grid.best_params_)
    print("Best val macro-F1:", float(grid.best_score_))

    y_pred = best_model.predict(X_test)

    report = make_eval_report(y_test, y_pred, labels=LABELS)

    OUT_DIR = FEATURES_DIR / "baseline_lr"
    OUT_DIR.mkdir(parents=True, exist_ok=True)

    joblib.dump(best_model, OUT_DIR / "model.joblib")
    save_eval_report(report, OUT_DIR / "eval_report.json")

    summary = {
        "best_params": grid.best_params_,
        "val_macro_f1": float(grid.best_score_),
        "test_macro_f1": report.macro_f1,
        "test_weighted_f1": report.weighted_f1,
        "test_label_counts": dict(Counter(y_test)),
        "pred_label_counts": dict(Counter(y_pred)),
    }
    (OUT_DIR / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")

    print("\n✅ Step 6 complete.")
    print("Test macro-F1:", report.macro_f1)
    print("Artifacts:", OUT_DIR)


if __name__ == "__main__":
    main()
