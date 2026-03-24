from __future__ import annotations

from pathlib import Path
import json
from collections import Counter

import numpy as np
import joblib

from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.linear_model import SGDClassifier
from sklearn.metrics import f1_score, classification_report, confusion_matrix


LABELS = [
    "BENIGN","DDoS","DoS","PortScan","BruteForce","WebAttack","Botnet","Infiltration","Heartbleed"
]
ATTACK_LABELS = [l for l in LABELS if l != "BENIGN"]


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

    # ---------- Stage 1: binary (ATTACK vs BENIGN) ----------
    y_train_bin = np.where(y_train == "BENIGN", "BENIGN", "ATTACK")
    y_val_bin   = np.where(y_val   == "BENIGN", "BENIGN", "ATTACK")
    y_test_bin  = np.where(y_test  == "BENIGN", "BENIGN", "ATTACK")

    stage1 = Pipeline(steps=[
        ("scaler", StandardScaler(with_mean=False)),
        ("clf", SGDClassifier(
            loss="log_loss",          # gives probabilities
            alpha=2e-5,
            penalty="l2",
            max_iter=4000,
            tol=1e-3,
            n_jobs=-1,
            class_weight="balanced",
            random_state=42,
        ))
    ])
    stage1.fit(X_train, y_train_bin)

    # choose threshold on VAL to control false positives while keeping recall
    proba_val_attack = stage1.predict_proba(X_val)[:, list(stage1.named_steps["clf"].classes_).index("ATTACK")]
    thresholds = np.linspace(0.10, 0.95, 18)

    best_t, best_score = 0.5, -1.0
    best_stats = None

    for t in thresholds:
        pred = np.where(proba_val_attack >= t, "ATTACK", "BENIGN")
        # objective: maximize macro-F1 on binary OR you can optimize attack precision/recall tradeoff
        score = f1_score(y_val_bin, pred, average="macro", zero_division=0)
        if score > best_score:
            best_score = score
            best_t = float(t)
            best_stats = classification_report(y_val_bin, pred, digits=4, zero_division=0)

    # Stage 1 test
    proba_test_attack = stage1.predict_proba(X_test)[:, list(stage1.named_steps["clf"].classes_).index("ATTACK")]
    pred_test_bin = np.where(proba_test_attack >= best_t, "ATTACK", "BENIGN")

    print("\n✅ Stage 1 (Binary) chosen threshold:", best_t)
    print("VAL binary report:\n", best_stats)
    print("TEST binary report:\n", classification_report(y_test_bin, pred_test_bin, digits=4, zero_division=0))

    # ---------- Stage 2: multiclass attack-type ----------
    # train only on attack samples
    tr_attack_mask = (y_train != "BENIGN")
    va_attack_mask = (y_val != "BENIGN")
    te_attack_mask = (y_test != "BENIGN")

    stage2 = Pipeline(steps=[
        ("scaler", StandardScaler(with_mean=False)),
        ("clf", SGDClassifier(
            loss="hinge",
            alpha=1e-5,
            penalty="l2",
            max_iter=4000,
            tol=1e-3,
            n_jobs=-1,
            class_weight="balanced",
            random_state=42,
        ))
    ])
    stage2.fit(X_train[tr_attack_mask], y_train[tr_attack_mask])

    # Optional: "unknown" gate for stage2 using decision_function margins
    # If top margin is too low, predict ATTACK_UNKNOWN
    UNKNOWN_MARGIN = 0.0  # start at 0, later tune on VAL

    # Build final predictions
    final_pred = np.array(["BENIGN"] * len(y_test), dtype=object)

    attack_idx = np.where(pred_test_bin == "ATTACK")[0]
    if len(attack_idx) > 0:
        # stage2 predicts subtype
        # decision_function gives margins; higher = more confident
        if hasattr(stage2.named_steps["clf"], "decision_function"):
            scores = stage2.named_steps["clf"].decision_function(stage2.named_steps["scaler"].transform(X_test[attack_idx]))
            # scores shape: (n_samples, n_classes)
            top = scores.max(axis=1)
            sub = stage2.predict(X_test[attack_idx])
            sub = sub.astype(object)

            sub[top < UNKNOWN_MARGIN] = "ATTACK_UNKNOWN"
            final_pred[attack_idx] = sub
        else:
            final_pred[attack_idx] = stage2.predict(X_test[attack_idx])

    # Evaluate multiclass (including unknown if present)
    # Macro-F1 on canonical labels only:
    mask_known = np.isin(final_pred, LABELS)
    if not mask_known.all():
        # map unknown to BENIGN? or exclude from macro-F1? Here we exclude unknown from macro-F1 calc.
        pass

    macro = float(f1_score(y_test, final_pred, labels=LABELS, average="macro", zero_division=0))
    weighted = float(f1_score(y_test, final_pred, labels=LABELS, average="weighted", zero_division=0))

    print("\n✅ Two-stage final (multiclass) complete.")
    print("TEST macro-F1:", macro)
    print("TEST weighted-F1:", weighted)
    print("\nPer-class report (TEST):\n", classification_report(y_test, final_pred, labels=LABELS, digits=4, zero_division=0))

    OUT_DIR = FEATURES_DIR / "two_stage_sgd"
    OUT_DIR.mkdir(parents=True, exist_ok=True)

    joblib.dump(
        {"stage1": stage1, "stage1_threshold": best_t, "stage2": stage2, "unknown_margin": UNKNOWN_MARGIN},
        OUT_DIR / "model.joblib"
    )

    save_json(OUT_DIR / "summary.json", {
        "stage1_threshold": best_t,
        "stage1_val_macro_f1": best_score,
        "test_macro_f1": macro,
        "test_weighted_f1": weighted,
        "test_label_counts": dict(Counter(y_test)),
        "pred_label_counts": dict(Counter(final_pred)),
    })

    print("Artifacts:", OUT_DIR)


if __name__ == "__main__":
    main()
