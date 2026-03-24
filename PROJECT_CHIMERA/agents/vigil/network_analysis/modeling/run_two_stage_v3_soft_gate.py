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

    # ---------------- Stage 1: Binary ATTACK vs BENIGN ----------------
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
    p_attack_val = stage1.predict_proba(X_val)[:, attack_col]

    # Choose TWO thresholds for alert levels (not for suppressing labels)
    # We keep defaults that work well generally; you can tune later.
    T_SUSPECT = 0.35
    T_CONFIRMED = 0.65

    # ---------------- Stage 2: Multiclass (your strong model) ----------------
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

    # Predict multiclass always
    pred_test_multi = stage2.predict(X_test)

    # Stage1 probabilities for alerting
    p_attack_test = stage1.predict_proba(X_test)[:, attack_col]

    # Optional: multiclass margin as confidence proxy (higher margin = more confident)
    # decision_function returns (n_samples, n_classes)
    scores = stage2.named_steps["clf"].decision_function(stage2.named_steps["scaler"].transform(X_test))
    top1 = scores.max(axis=1)
    # get 2nd best without heavy sort
    part = np.partition(scores, -2, axis=1)
    top2 = part[:, -2]
    margin = (top1 - top2).astype(np.float32)

    # Build alert levels
    alert_level = np.full(len(X_test), "NONE", dtype=object)
    is_attack_label = pred_test_multi != "BENIGN"

    # if model says attack but stage1 low => SUSPECT (not suppressed)
    alert_level[(is_attack_label) & (p_attack_test >= T_SUSPECT)] = "SUSPECT"
    alert_level[(is_attack_label) & (p_attack_test >= T_CONFIRMED)] = "CONFIRMED"

    # If multiclass predicts BENIGN but stage1 is very high => suspicious anyway
    alert_level[(~is_attack_label) & (p_attack_test >= T_CONFIRMED)] = "SUSPECT"

    # Final label is multiclass prediction (never suppressed)
    final_pred = pred_test_multi

    test_macro = float(f1_score(y_test, final_pred, labels=LABELS, average="macro", zero_division=0))
    test_weighted = float(f1_score(y_test, final_pred, labels=LABELS, average="weighted", zero_division=0))

    print("\n✅ Two-stage v3 (soft gate) complete.")
    print("TEST macro-F1:", test_macro)
    print("TEST weighted-F1:", test_weighted)
    print("\nFinal multiclass TEST:\n", classification_report(y_test, final_pred, labels=LABELS, digits=4, zero_division=0))

    # Also report alert distribution
    print("\nAlert levels:", dict(Counter(alert_level)))

    OUT_DIR = FEATURES_DIR / "two_stage_soft_gate"
    OUT_DIR.mkdir(parents=True, exist_ok=True)

    joblib.dump(
        {"stage1": stage1, "stage2": stage2, "labels": LABELS,
         "thresholds": {"suspect": T_SUSPECT, "confirmed": T_CONFIRMED}},
        OUT_DIR / "model.joblib"
    )

    save_json(OUT_DIR / "summary.json", {
        "test_macro_f1": test_macro,
        "test_weighted_f1": test_weighted,
        "thresholds": {"suspect": T_SUSPECT, "confirmed": T_CONFIRMED},
        "alert_level_counts": dict(Counter(alert_level)),
        "test_label_counts": dict(Counter(y_test)),
        "pred_label_counts": dict(Counter(final_pred)),
        "notes": "Soft gate: stage1 controls alert severity, not label suppression.",
    })

    # Save a small sample of scored outputs for inspection
    sample_n = 5000 if len(X_test) > 5000 else len(X_test)
    idx = np.random.default_rng(42).choice(len(X_test), size=sample_n, replace=False)
    save_json(OUT_DIR / "sample_scored.json", {
        "p_attack": p_attack_test[idx].tolist(),
        "margin": margin[idx].tolist(),
        "y_true": y_test[idx].tolist(),
        "y_pred": final_pred[idx].tolist(),
        "alert_level": alert_level[idx].tolist(),
    })

    print("Artifacts:", OUT_DIR)


if __name__ == "__main__":
    main()
