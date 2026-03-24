from __future__ import annotations

from pathlib import Path
import json
from collections import Counter

import numpy as np
import joblib

from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import f1_score

from evaluate_utils import make_eval_report, save_eval_report


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


def load_npz_X(path: Path, as_float32: bool = True) -> np.ndarray:
    X = np.load(path, allow_pickle=False)["X"]
    # Reduce RAM use
    if as_float32 and X.dtype != np.float32:
        X = X.astype(np.float32, copy=False)
    return X


def pick_thresholds_per_class(proba_val: np.ndarray, y_val_idx: np.ndarray, n_classes: int) -> np.ndarray:
    thresholds = np.zeros(n_classes, dtype=np.float32)
    grid = np.linspace(0.05, 0.95, 19, dtype=np.float32)

    for k in range(n_classes):
        y_true = (y_val_idx == k).astype(np.int8, copy=False)
        scores = proba_val[:, k]

        best_t = np.float32(0.5)
        best_f1 = -1.0

        for t in grid:
            y_pred = (scores >= t).astype(np.int8, copy=False)
            f1 = f1_score(y_true, y_pred, zero_division=0)
            if f1 > best_f1:
                best_f1 = f1
                best_t = t

        thresholds[k] = best_t

    return thresholds


def predict_with_thresholds(proba: np.ndarray, thresholds: np.ndarray) -> np.ndarray:
    passes = proba >= thresholds[None, :]
    y_pred = np.empty(proba.shape[0], dtype=np.int32)

    for i in range(proba.shape[0]):
        if passes[i].any():
            idxs = np.where(passes[i])[0]
            y_pred[i] = int(idxs[np.argmax(proba[i, idxs])])
        else:
            y_pred[i] = int(np.argmax(proba[i]))
    return y_pred


def main():
    FEATURES_DIR = Path(
        r"C:\Users\naren\Downloads\PROJECTS\PROJECT_CHIMERA\agents\vigil\network_analysis\datasets\processed\features\cicids2017_v1_covsplit"
    )

    # Load as float32 to cut memory
    X_train = load_npz_X(FEATURES_DIR / "X_train.npz", as_float32=True)
    y_train = np.load(FEATURES_DIR / "y_train.npy", allow_pickle=True).astype(str)

    X_val = load_npz_X(FEATURES_DIR / "X_val.npz", as_float32=True)
    y_val = np.load(FEATURES_DIR / "y_val.npy", allow_pickle=True).astype(str)

    X_test = load_npz_X(FEATURES_DIR / "X_test.npz", as_float32=True)
    y_test = np.load(FEATURES_DIR / "y_test.npy", allow_pickle=True).astype(str)

    # Encode labels using fixed LABELS ordering
    le = LabelEncoder()
    le.fit(LABELS)

    y_train_idx = le.transform(y_train).astype(np.int32, copy=False)
    y_val_idx = le.transform(y_val).astype(np.int32, copy=False)
    y_test_idx = le.transform(y_test).astype(np.int32, copy=False)

    # IMPORTANT: disable early stopping to avoid internal train_test_split + memory spikes
    model = HistGradientBoostingClassifier(
        learning_rate=0.08,
        max_depth=8,
        max_iter=220,
        min_samples_leaf=30,
        random_state=42,
        early_stopping=False,          # ✅ key fix
        validation_fraction=None,      # not used when early_stopping=False
    )

    model.fit(X_train, y_train_idx)

    # Probabilities
    proba_val = model.predict_proba(X_val)
    proba_test = model.predict_proba(X_test)

    # Threshold calibration on VAL
    thresholds = pick_thresholds_per_class(proba_val, y_val_idx, n_classes=len(LABELS))

    # Predictions
    y_pred_val = predict_with_thresholds(proba_val, thresholds)
    y_pred_test = predict_with_thresholds(proba_test, thresholds)

    val_macro = float(f1_score(y_val_idx, y_pred_val, average="macro", zero_division=0))
    test_macro = float(f1_score(y_test_idx, y_pred_test, average="macro", zero_division=0))

    print("\n✅ HGB baseline complete.")
    print("VAL macro-F1:", val_macro)
    print("TEST macro-F1:", test_macro)

    # Save reports (string labels)
    y_pred_test_str = le.inverse_transform(y_pred_test)
    report = make_eval_report(y_test, y_pred_test_str, labels=LABELS)

    OUT_DIR = FEATURES_DIR / "baseline_hgb"
    OUT_DIR.mkdir(parents=True, exist_ok=True)

    joblib.dump({"model": model, "label_encoder": le, "thresholds": thresholds}, OUT_DIR / "model.joblib")
    save_eval_report(report, OUT_DIR / "eval_report.json")

    summary = {
        "val_macro_f1": val_macro,
        "test_macro_f1": report.macro_f1,
        "test_weighted_f1": report.weighted_f1,
        "thresholds": {LABELS[i]: float(thresholds[i]) for i in range(len(LABELS))},
        "test_label_counts": dict(Counter(y_test)),
        "pred_label_counts": dict(Counter(y_pred_test_str)),
    }
    (OUT_DIR / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")

    print("Artifacts:", OUT_DIR)


if __name__ == "__main__":
    main()
