from __future__ import annotations

from pathlib import Path
import json
from collections import Counter

import numpy as np
import joblib

from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.linear_model import SGDClassifier
from sklearn.metrics import f1_score, classification_report

LABELS = [
    "BENIGN","DDoS","DoS","PortScan","BruteForce","WebAttack","Botnet","Infiltration","Heartbleed"
]

def load_npz_X(path: Path) -> np.ndarray:
    X = np.load(path, allow_pickle=False)["X"]
    if X.dtype != np.float32:
        X = X.astype(np.float32, copy=False)
    return X

def save_json(path: Path, obj) -> None:
    path.write_text(json.dumps(obj, indent=2), encoding="utf-8")

def main():
    FEATURES_DIR = Path(
        r"C:\Users\naren\Downloads\PROJECTS\PROJECT_CHIMERA\agents\vigil\network_analysis\datasets\processed\features\cicids2017_v1_covsplit"
    )

    X_train = load_npz_X(FEATURES_DIR / "X_train.npz")
    y_train = np.load(FEATURES_DIR / "y_train.npy", allow_pickle=True).astype(str)

    X_val = load_npz_X(FEATURES_DIR / "X_val.npz")
    y_val = np.load(FEATURES_DIR / "y_val.npy", allow_pickle=True).astype(str)

    X_test = load_npz_X(FEATURES_DIR / "X_test.npz")
    y_test = np.load(FEATURES_DIR / "y_test.npy", allow_pickle=True).astype(str)

    # ---------------- Stage 1: Binary gate (ATTACK vs BENIGN) ----------------
    y_train_bin = np.where(y_train == "BENIGN", "BENIGN", "ATTACK")
    y_val_bin   = np.where(y_val   == "BENIGN", "BENIGN", "ATTACK")
    y_test_bin  = np.where(y_test  == "BENIGN", "BENIGN", "ATTACK")

    stage1 = Pipeline(steps=[
        ("scaler", StandardScaler(with_mean=False)),
        ("clf", SGDClassifier(
            loss="log_loss",
            alpha=2e-5,
            penalty="l2",
            max_iter=5000,
            tol=1e-3,
            n_jobs=-1,
            class_weight="balanced",
            random_state=42,
        ))
    ])
    stage1.fit(X_train, y_train_bin)

    attack_col = list(stage1.named_steps["clf"].classes_).index("ATTACK")
    proba_val_attack = stage1.predict_proba(X_val)[:, attack_col]

    # pick threshold to maximize binary macro-F1 on VAL (same as your v1 approach)
    thresholds = np.linspace(0.10, 0.95, 18)
    best_t, best_val_bin_macro = 0.5, -1.0
    for t in thresholds:
        pred = np.where(proba_val_attack >= t, "ATTACK", "BENIGN")
        score = f1_score(y_val_bin, pred, average="macro", zero_division=0)
        if score > best_val_bin_macro:
            best_val_bin_macro = score
            best_t = float(t)

    # ---------------- Stage 2: Multiclass model (train on ALL labels) ----------------
    # This is basically your baseline_sgd_svm model (the one that worked well).
    stage2 = Pipeline(steps=[
        ("scaler", StandardScaler(with_mean=False)),
        ("clf", SGDClassifier(
            loss="hinge",
            alpha=1e-5,
            penalty="l2",
            max_iter=5000,
            tol=1e-3,
            n_jobs=-1,
            class_weight="balanced",
            random_state=42,
        ))
    ])
    stage2.fit(X_train, y_train)

    # ---------------- Final: gate then subtype ----------------
    proba_test_attack = stage1.predict_proba(X_test)[:, attack_col]
    gate_attack = proba_test_attack >= best_t

    final_pred = np.array(["BENIGN"] * len(y_test), dtype=object)
    if gate_attack.any():
        final_pred[gate_attack] = stage2.predict(X_test[gate_attack])

    # Evaluate
    test_macro = float(f1_score(y_test, final_pred, labels=LABELS, average="macro", zero_division=0))
    test_weighted = float(f1_score(y_test, final_pred, labels=LABELS, average="weighted", zero_division=0))

    print("\n✅ Two-stage v2 (gate + multiclass) complete.")
    print("Chosen gate threshold:", best_t)
    print("TEST macro-F1:", test_macro)
    print("TEST weighted-F1:", test_weighted)

    print("\nStage 1 (binary) TEST:\n", classification_report(y_test_bin, np.where(gate_attack, "ATTACK", "BENIGN"),
                                                          digits=4, zero_division=0))
    print("\nFinal multiclass TEST:\n", classification_report(y_test, final_pred, labels=LABELS,
                                                             digits=4, zero_division=0))

    OUT_DIR = FEATURES_DIR / "two_stage_gate_multiclass"
    OUT_DIR.mkdir(parents=True, exist_ok=True)

    joblib.dump(
        {"stage1": stage1, "stage1_threshold": best_t, "stage2": stage2, "labels": LABELS},
        OUT_DIR / "model.joblib"
    )

    save_json(OUT_DIR / "summary.json", {
        "stage1_threshold": best_t,
        "val_binary_macro_f1": best_val_bin_macro,
        "test_macro_f1": test_macro,
        "test_weighted_f1": test_weighted,
        "test_label_counts": dict(Counter(y_test)),
        "pred_label_counts": dict(Counter(final_pred)),
    })

    print("Artifacts:", OUT_DIR)

if __name__ == "__main__":
    main()
