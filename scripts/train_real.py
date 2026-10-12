"""실제 데이터(Loghub OpenSSH)로 '공격 지속 여부' 모델 학습.

평가
  - 시간 순 롤링 교차검증(5구간 중 앞 k구간 학습 → k+1구간 테스트, 4개 폴드)
    단일 분할은 마지막 1주에 단순 공격이 몰려 정확도가 0.95로 부풀었다(v4).
  - 기준선 2개와 비교: 다수 클래스, 규칙(실패 20회 이상이면 계속 공격)
  - 최종 모델은 앞 80% 기간으로 학습, 마지막 20% 기간이 홀드아웃

피처
  - 윈도우 피처(loginguard.features.FEATURE_NAMES)
  - IP 이력 피처(HISTORY_FEATURE_NAMES): 과거 윈도우만 사용, 미래 정보 없음

사용법: python scripts/train_real.py --data data/real_windows.jsonl [--drop a,b] [--no-history]
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import joblib
import numpy as np
import sklearn
from sklearn.ensemble import HistGradientBoostingClassifier, RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (accuracy_score, balanced_accuracy_score, confusion_matrix,
                             f1_score, precision_score, recall_score)
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from loginguard.features import (FEATURE_NAMES, HISTORY_FEATURE_NAMES, RULE_BLOCK_FAILS,  # noqa: E402
                                 IPHistory, extract_features, window_bounds)

N_CHUNKS = 5


def load(path):
    """시간 순으로 훑으며 윈도우 피처 + (그 시점까지의) IP 이력 피처를 만든다."""
    rows = [json.loads(line) for line in open(path)]
    rows.sort(key=lambda r: r["ts"])
    hist = IPHistory()
    feats, y, ts, known = [], [], [], []
    for r in rows:
        start, end, n_fail = window_bounds(r["events"])
        f = extract_features(r["events"])
        f.update(hist.features(r["ip"], start))
        if n_fail > 0:                  # 서빙(app/main.py)과 같은 규칙: 실패 윈도우만 이력에 기록
            hist.add(r["ip"], start, end, n_fail)
        if r["label"] is None:          # 수집 공백으로 정답을 모르는 윈도우: 이력에만 사용
            continue
        feats.append(f)
        y.append(r["label"])
        ts.append(start)
        known.append(r.get("known_user", False))
    return feats, np.array(y), np.array(ts), np.array(known)


def metrics(y, p):
    tn, fp, fn, tp = confusion_matrix(y, p, labels=[0, 1]).ravel()
    return {"accuracy": round(accuracy_score(y, p), 4),
            "balanced_accuracy": round(balanced_accuracy_score(y, p), 4),
            "precision": round(precision_score(y, p, zero_division=0), 4),
            "recall": round(recall_score(y, p, zero_division=0), 4),
            "f1": round(f1_score(y, p, zero_division=0), 4),
            "confusion_matrix": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)}}


def candidates(seed):
    return {
        "logistic_regression": make_pipeline(StandardScaler(), LogisticRegression(max_iter=3000, class_weight="balanced")),
        "random_forest": RandomForestClassifier(n_estimators=400, min_samples_leaf=5, class_weight="balanced",
                                                random_state=seed, n_jobs=-1),
        "hist_gradient_boosting": HistGradientBoostingClassifier(max_depth=4, learning_rate=0.06, max_iter=300,
                                                                 class_weight="balanced", random_state=seed),
    }


def folds(ts):
    q = np.quantile(ts, np.linspace(0, 1, N_CHUNKS + 1))
    for k in range(1, N_CHUNKS):
        tr = ts < q[k]
        te = (ts >= q[k]) & ((ts < q[k + 1]) if k < N_CHUNKS - 1 else (ts <= q[k + 1]))
        yield k, tr, te


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", default="data/real_windows.jsonl")
    ap.add_argument("--out-dir", default="models")
    ap.add_argument("--drop", default="")
    ap.add_argument("--no-history", action="store_true")
    ap.add_argument("--seed", type=int, default=42)
    a = ap.parse_args()

    drop = {d for d in a.drop.split(",") if d}
    names = [n for n in FEATURE_NAMES + ([] if a.no_history else HISTORY_FEATURE_NAMES) if n not in drop]
    feats, y, ts, known = load(a.data)
    X = np.array([[f[n] for n in names] for f in feats])
    n_fail = np.array([round(f["fail_ratio"] * f["n_attempts"]) for f in feats])
    print(f"윈도우 {len(y)}개 (계속 공격 {y.mean():.1%}) | 피처 {len(names)}개\n")

    cv = {"baseline_majority": [], "baseline_rule_20fails": [], **{n: [] for n in candidates(0)}}
    for k, tr, te in folds(ts):
        maj = int(y[tr].mean() >= 0.5)
        cv["baseline_majority"].append(accuracy_score(y[te], np.full(te.sum(), maj)))
        cv["baseline_rule_20fails"].append(accuracy_score(y[te], n_fail[te] >= RULE_BLOCK_FAILS))
        for name, model in candidates(a.seed).items():
            model.fit(X[tr], y[tr])
            cv[name].append(accuracy_score(y[te], model.predict(X[te])))
    print("시간 순 롤링 교차검증 (정확도, 폴드 1~4)")
    for name, accs in cv.items():
        print(f"  {name:24s} mean={np.mean(accs):.4f} ±{np.std(accs):.4f}  " + " ".join(f"{x:.3f}" for x in accs))

    model_names = list(candidates(0))
    best = max(model_names, key=lambda n: np.mean(cv[n]))

    # 최종: 앞 80% 학습, 마지막 20% 홀드아웃
    *_, (k, tr, te) = folds(ts)
    model = candidates(a.seed)[best].fit(X[tr], y[tr])
    pred = model.predict(X[te])
    hold = metrics(y[te], pred)
    hold["train_accuracy"] = round(accuracy_score(y[tr], model.predict(X[tr])), 4)

    # 성공이 포함된 윈도우 / 실패만 있는 윈도우별 정확도
    has_succ = np.array([f["fail_ratio"] < 1.0 for f in feats])
    sub = {}
    for name, mask in (("windows_with_success", has_succ[te]), ("windows_fail_only", ~has_succ[te])):
        sub[name] = {"n": int(mask.sum()), "accuracy": round(accuracy_score(y[te][mask], pred[mask]), 4)}
    # 정상 사용자(28일 중 로그인 성공한 IP) 윈도우를 차단으로 판정한 비율 — 전 기간, 롤링 예측 기준
    oof = np.full(len(y), -1)
    for _, ftr, fte in folds(ts):
        oof[fte] = candidates(a.seed)[best].fit(X[ftr], y[ftr]).predict(X[fte])
    km = known & (oof >= 0)
    sub["known_user_block_rate"] = {"n": int(km.sum()), "rate": round(float((oof[km] == 1).mean()), 4)}
    hold["subsets"] = sub
    print("세부:", json.dumps(sub, ensure_ascii=False))
    print(f"\n최고 모델: {best} | 홀드아웃 acc={hold['accuracy']:.4f} bal_acc={hold['balanced_accuracy']:.4f} "
          f"P={hold['precision']:.3f} R={hold['recall']:.3f} F1={hold['f1']:.3f} (train_acc={hold['train_accuracy']:.4f})")

    out = Path(a.out_dir)
    out.mkdir(parents=True, exist_ok=True)
    joblib.dump({"model": model, "feature_names": names, "model_name": best,
                 "sklearn_version": sklearn.__version__}, out / "model.joblib", compress=3)
    (out / "metrics.json").write_text(json.dumps(
        {"dataset": "Loghub OpenSSH (real sshd log, LabSZ, 2015-12-10 ~ 2016-01-07)",
         "task": "10분 윈도우(성공·실패 모두) 후 1시간 안에 같은 IP가 다시 와서 로그인 실패를 일으키는가",
         "best_model": best, "feature_names": names,
         "cv_accuracy": {n: {"mean": round(float(np.mean(v)), 4), "std": round(float(np.std(v)), 4),
                             "folds": [round(float(x), 4) for x in v]} for n, v in cv.items()},
         "holdout": hold, "sklearn_version": sklearn.__version__},
        ensure_ascii=False, indent=2))
    print(f"저장: {out/'model.joblib'}, {out/'metrics.json'}")


if __name__ == "__main__":
    main()
