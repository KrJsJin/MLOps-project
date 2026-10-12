"""피처 추출 → 모델 비교 → 최고 모델 저장.

- 기본은 규칙으로 판정되지 않는 회색지대(triage == "model")만 사용
- 시간 순 분할: 앞 24일 학습 / 뒤 6일 테스트 (미래 데이터를 학습에 쓰지 않기 위함)
- 후보 모델: 로지스틱 회귀, 랜덤 포레스트, HistGradientBoosting
- 결과: models/model.joblib, models/metrics.json

사용법: python scripts/train_synthetic.py --data data/login_windows.jsonl [--drop 피처1,피처2]
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import joblib
import numpy as np
from sklearn.ensemble import HistGradientBoostingClassifier, RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (accuracy_score, confusion_matrix, f1_score,
                             precision_score, recall_score)
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from loginguard.features import FEATURE_NAMES, extract_features, triage  # noqa: E402

TRAIN_DAYS = 24


def load(path, feature_names, zone="model"):
    """zone="model": 규칙으로 걸러지지 않는 회색지대만 학습/평가 (문제 재정의 v2).
    zone="all": 전체 윈도우 (문제 정의 v1)."""
    X, y, day, scen = [], [], [], []
    with open(path) as f:
        for line in f:
            r = json.loads(line)
            feats = extract_features(r["events"])
            if zone != "all" and triage(feats) != zone:
                continue
            X.append([feats[n] for n in feature_names])
            y.append(r["label"])
            day.append(r["day"])
            scen.append(r["scenario"])
    return np.array(X), np.array(y), np.array(day), np.array(scen)


def candidates(seed):
    return {
        "logistic_regression": make_pipeline(StandardScaler(), LogisticRegression(max_iter=2000)),
        "random_forest": RandomForestClassifier(n_estimators=300, min_samples_leaf=5,
                                                random_state=seed, n_jobs=-1),
        "hist_gradient_boosting": HistGradientBoostingClassifier(max_depth=4, learning_rate=0.08,
                                                                 max_iter=250, random_state=seed),
    }


def metrics(y, p):
    tn, fp, fn, tp = confusion_matrix(y, p).ravel()
    return {"accuracy": round(accuracy_score(y, p), 4),
            "precision": round(precision_score(y, p), 4),
            "recall": round(recall_score(y, p), 4),
            "f1": round(f1_score(y, p), 4),
            "confusion_matrix": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)}}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", default="data/login_windows.jsonl")
    ap.add_argument("--out-dir", default="models")
    ap.add_argument("--drop", default="", help="제외할 피처(쉼표 구분)")
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--zone", default="model", choices=["model", "all"])
    a = ap.parse_args()

    drop = {d for d in a.drop.split(",") if d}
    names = [n for n in FEATURE_NAMES if n not in drop]
    X, y, day, scen = load(a.data, names, a.zone)
    tr, te = day < TRAIN_DAYS, day >= TRAIN_DAYS
    print(f"학습 {tr.sum()} / 테스트 {te.sum()}  | 피처 {len(names)}개: {names}")

    results, fitted = {}, {}
    for name, model in candidates(a.seed).items():
        model.fit(X[tr], y[tr])
        tr_acc = accuracy_score(y[tr], model.predict(X[tr]))
        m = metrics(y[te], model.predict(X[te]))
        m["train_accuracy"] = round(tr_acc, 4)
        results[name], fitted[name] = m, model
        print(f"{name:24s} train_acc={tr_acc:.4f}  test_acc={m['accuracy']:.4f}  "
              f"P={m['precision']:.3f} R={m['recall']:.3f} F1={m['f1']:.3f}")

    best = max(results, key=lambda k: results[k]["f1"])
    model = fitted[best]
    pred = model.predict(X[te])

    # 시나리오별 정확도 — 어떤 유형에서 틀리는지 확인
    per_scen = {s: round(float((pred[scen[te] == s] == y[te][scen[te] == s]).mean()), 3)
                for s in sorted(set(scen[te]))}
    print(f"\n최고 모델: {best}")
    for s, acc in per_scen.items():
        print(f"  {s:26s} {acc:.3f}")

    out = Path(a.out_dir)
    out.mkdir(parents=True, exist_ok=True)
    joblib.dump({"model": model, "feature_names": names, "model_name": best}, out / "model.joblib", compress=3)
    (out / "metrics.json").write_text(json.dumps(
        {"best_model": best, "zone": a.zone, "feature_names": names, "test": results[best],
         "all_models": results, "per_scenario_accuracy": per_scen},
        ensure_ascii=False, indent=2))
    print(f"\n저장: {out/'model.joblib'}, {out/'metrics.json'}")


if __name__ == "__main__":
    main()
