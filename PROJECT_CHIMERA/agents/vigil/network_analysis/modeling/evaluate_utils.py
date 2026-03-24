from __future__ import annotations

import json
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Dict, List

import numpy as np
from sklearn.metrics import (
    f1_score,
    classification_report,
    confusion_matrix,
)


@dataclass
class EvalReport:
    macro_f1: float
    weighted_f1: float
    labels: List[str]
    confusion_matrix: List[List[int]]
    per_class: Dict[str, Dict[str, float]]  # precision/recall/f1/support
    notes: Dict[str, str]


def make_eval_report(y_true: np.ndarray, y_pred: np.ndarray, labels: List[str]) -> EvalReport:
    macro = float(f1_score(y_true, y_pred, average="macro"))
    weighted = float(f1_score(y_true, y_pred, average="weighted"))

    # classification_report returns string or dict; use dict
    cr = classification_report(y_true, y_pred, labels=labels, output_dict=True, zero_division=0)
    cm = confusion_matrix(y_true, y_pred, labels=labels)

    # keep only per-class entries (exclude accuracy/macro avg/weighted avg)
    per_class = {}
    for lab in labels:
        if lab in cr:
            per_class[lab] = {
                "precision": float(cr[lab]["precision"]),
                "recall": float(cr[lab]["recall"]),
                "f1": float(cr[lab]["f1-score"]),
                "support": float(cr[lab]["support"]),
            }

    return EvalReport(
        macro_f1=macro,
        weighted_f1=weighted,
        labels=labels,
        confusion_matrix=cm.tolist(),
        per_class=per_class,
        notes={
            "primary_metric": "macro_f1",
            "why_macro_f1": "CICIDS2017 is imbalanced; macro-F1 weights each class equally.",
        },
    )


def save_eval_report(report: EvalReport, out_path: Path) -> None:
    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(asdict(report), indent=2), encoding="utf-8")
