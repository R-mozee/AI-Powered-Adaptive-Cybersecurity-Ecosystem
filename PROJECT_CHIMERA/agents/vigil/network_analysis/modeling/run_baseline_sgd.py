from __future__ import annotations

from pathlib import Path
import json
from collections import Counter

import numpy as np
import joblib

from sklearn.linear_model import SGDClassifier
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import f1_score
from sklearn.utils.class_weight import compute_class_weight

from evaluate_utils import make_eval_report, save_eval_report


LABELS = [
    "BENIGN","DDoS","DoS","PortScan","BruteForce","WebAttack","Botnet","Infiltration","Heartbleed"
]


def load_npz_X(path: Path) -> np.ndarray:
    X = np.load(path, allow_pickle=False)["X"]
    # use float32 to save RAM
    if X.dtype != np.float32:
        X = X.astype(np.float32, copy=False)
    return X


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

    # class weights for imbalance
    classes = np.array(LABELS, dtype=object)
    cw = compute_class_weight(class_weight="balanced", classes=classes, y=y_train)
    class_weight = {cls: float(w) for cls, w in zip(classes, cw)}

    # Linear SVM via SGD (hinge loss), scaled features
    model = Pipeline(steps=[
        ("scaler", StandardScaler(with_mean=False)),  # with_mean=False keeps it safe for large arrays
        ("clf", SGDClassifier(
            loss="hinge",
            alpha=1e-5,
            penalty="l2",
            max_iter=3000,
            tol=1e-3,
            n_jobs=-1,
            class_weight=class_weight,
            random_state=42,
        ))
    ])

    model.fit(X_train, y_train)

    y_pred_val = model.predict(X_val)
    y_pred_test = model.predict(X_test)

    val_macro = float(f1_score(y_val, y_pred_val, average="macro", zero_division=0))
    test_macro = float(f1_score(y_test, y_pred_test, average="macro", zero_division=0))

    print("\n✅ SGD-SVM baseline complete.")
    print("VAL macro-F1:", val_macro)
    print("TEST macro-F1:", test_macro)

    report = make_eval_report(y_test, y_pred_test, labels=LABELS)

    OUT_DIR = FEATURES_DIR / "baseline_sgd_svm"
    OUT_DIR.mkdir(parents=True, exist_ok=True)

    joblib.dump(model, OUT_DIR / "model.joblib")
    save_eval_report(report, OUT_DIR / "eval_report.json")

    summary = {
        "val_macro_f1": val_macro,
        "test_macro_f1": report.macro_f1,
        "test_weighted_f1": report.weighted_f1,
        "test_label_counts": dict(Counter(y_test)),
        "pred_label_counts": dict(Counter(y_pred_test)),
        "class_weight": class_weight,
    }
    (OUT_DIR / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")

    print("Artifacts:", OUT_DIR)


if __name__ == "__main__":
    main()
