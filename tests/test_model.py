"""학습된 모델 품질 회귀 테스트 (재학습 후 품질이 떨어지면 실패)."""
import json
from pathlib import Path

import joblib

from loginguard.features import IPHistory, extract_features

ROOT = Path(__file__).resolve().parents[1]
METRICS = json.loads((ROOT / "models" / "metrics.json").read_text())
BUNDLE = joblib.load(ROOT / "models" / "model.joblib")


def test_cv_accuracy_meets_target_and_beats_baselines():
    cv = METRICS["cv_accuracy"]
    best = cv[METRICS["best_model"]]["mean"]
    assert best >= 0.85
    assert best > cv["baseline_majority"]["mean"]
    assert best > cv["baseline_rule_20fails"]["mean"]


def test_lag_label_feature_not_used():
    # 직전 윈도우의 정답을 담은 피처는 모델 입력에서 제외되어야 한다 (README 3장 참고)
    assert "hist_hours_since_prev" not in BUNDLE["feature_names"]


def _prob(events, hist):
    f = extract_features(events)
    f.update(hist)
    return BUNDLE["model"].predict_proba([[f[n] for n in BUNDLE["feature_names"]]])[0][1]


def test_persistent_attacker_scores_higher_than_one_off():
    one_off = [{"ts": i * 30, "user": "admin", "result": "fail", "invalid_user": False} for i in range(2)]
    heavy = [{"ts": i * 3, "user": "root", "result": "fail"} for i in range(15)]
    h = IPHistory()
    for k in range(5):
        h.add("x", k * 700, k * 700 + 500, 100)
    p_one = _prob(one_off, IPHistory().features("y", 0))
    p_heavy = _prob(heavy, h.features("x", 5 * 700))
    assert p_heavy > p_one
