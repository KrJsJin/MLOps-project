"""로그인 이벤트 → 모델 입력 피처 변환.

학습(scripts/train_real.py)과 서빙(app/main.py)이 **같은 함수**를 쓰도록 이 모듈 하나로 모아 둔다.
(training-serving skew 방지)

입력 단위: 한 출발지 IP가 최근 10분(WINDOW_SECONDS) 동안 남긴 SSH 로그인 이벤트 목록.
"""
from __future__ import annotations

from datetime import datetime, timezone
import math
from statistics import mean, pstdev
from typing import Iterable, Mapping

WINDOW_SECONDS = 600

# 공격 도구가 사전(dictionary)으로 자주 시도하는 계정명
PRIVILEGED_USERS = {
    "root", "admin", "administrator", "test", "user", "guest", "oracle",
    "postgres", "ubuntu", "ftp", "pi", "support", "mysql", "git",
}

FEATURE_NAMES = [
    "n_attempts",            # 윈도우 내 시도 횟수
    "fail_ratio",            # 실패 비율
    "n_unique_users",        # 시도한 서로 다른 계정 수
    "invalid_user_ratio",    # 존재하지 않는 계정 비율
    "privileged_user_ratio", # root/admin 등 사전 계정 비율
    "password_ratio",        # 공개키가 아닌 비밀번호 인증 비율
    "mean_interval_s",       # 시도 간 평균 간격(초)
    "interval_cv",           # 간격 변동계수(낮을수록 기계적으로 일정)
    "success_after_fails",   # 실패 3회 이상 뒤 성공 여부
    # night_ratio(새벽 시도 비율)는 v3에서 제외: 봇은 24시간 공격하고 관리자도 새벽에 접속해
    # 기여도가 0에 가까웠다 (permutation importance 0.0006).
]


def _to_epoch(ts) -> float:
    if isinstance(ts, (int, float)):
        return float(ts)
    dt = datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.timestamp()


def extract_features(events: Iterable[Mapping]) -> dict[str, float]:
    """이벤트 목록 하나(=IP 하나, 윈도우 하나)를 피처 dict로 변환한다.

    각 이벤트 필드:
      ts            ISO8601 문자열 또는 epoch 초
      user          시도한 계정명
      result        "success" | "fail"
      invalid_user  존재하지 않는 계정이면 True (sshd 'Invalid user' 로그)
      method        "password" | "publickey"
    """
    evs = sorted(events, key=lambda e: _to_epoch(e["ts"]))
    if not evs:
        raise ValueError("events가 비어 있습니다")

    n = len(evs)
    times = [_to_epoch(e["ts"]) for e in evs]
    users = [str(e["user"]).lower() for e in evs]
    fails = [e["result"] != "success" for e in evs]

    intervals = [b - a for a, b in zip(times, times[1:])]
    if intervals:
        m = mean(intervals)
        cv = (pstdev(intervals) / m) if m > 0 else 0.0
    else:
        m, cv = float(WINDOW_SECONDS), 1.0  # 단발성 시도: 간격 정보 없음

    success_after_fails = 0.0
    streak = 0
    for f in fails:
        if f:
            streak += 1
        else:
            if streak >= 3:
                success_after_fails = 1.0
            streak = 0

    return {
        "n_attempts": float(n),
        "fail_ratio": sum(fails) / n,
        "n_unique_users": float(len(set(users))),
        "invalid_user_ratio": sum(bool(e.get("invalid_user", False)) for e in evs) / n,
        "privileged_user_ratio": sum(u in PRIVILEGED_USERS for u in users) / n,
        "password_ratio": sum(e.get("method", "password") == "password" for e in evs) / n,
        "mean_interval_s": float(m),
        "interval_cv": float(cv),
        "success_after_fails": success_after_fails,
    }


RULE_BLOCK_FAILS = 20  # 10분 내 실패 20회 이상 → 모델 없이 즉시 차단 (안전망)


def triage(feats: Mapping[str, float]) -> str:
    """규칙으로 판정이 끝나는 구간과 모델이 판단할 구간을 나눈다.

    - "rule_block": 실패가 RULE_BLOCK_FAILS회 이상 → 명백한 무차별 대입, 즉시 차단
    - "model": 나머지 전부 — 성공만 있는 윈도우도 포함 (v7부터)
      v6까지는 실패 0회를 무조건 허용했지만, 오래 공격하던 IP가 성공한 경우를 놓쳐서 없앴다.
    """
    n_fail = round(feats["fail_ratio"] * feats["n_attempts"])
    if n_fail >= RULE_BLOCK_FAILS:
        return "rule_block"
    return "model"


ALERT_PRIOR_FAILS = 20  # 과거+이번 실패가 이 이상인 IP가 성공하면 침입 의심 경보


def success_alert(feats: Mapping[str, float]) -> bool:
    """공격 이력이 있는 IP의 로그인 성공 = 계정 탈취 의심.

    실제 데이터에 '침입 성공' 정답이 없어 학습 대신 규칙으로 둔다. 차단이 아니라
    보안 담당자 확인용 경보다. 정상 사용자 성공 146건에서 오경보 0건 (README 참고).
    """
    has_success = feats["fail_ratio"] < 1.0
    prior_fails = math.expm1(feats.get("hist_log_fails", 0.0))
    window_fails = feats["fail_ratio"] * feats["n_attempts"]
    # 윈도우 안 '실패 3회 뒤 성공'만으로는 오타 친 정상 사용자도 걸려서(실제 데이터 1건) 누적 기준으로 판단
    return has_success and (prior_fails + window_fails) >= ALERT_PRIOR_FAILS


def to_vector(feats: Mapping[str, float]) -> list[float]:
    return [float(feats[name]) for name in FEATURE_NAMES]


# ---------------------------------------------------------------------------
# IP 이력 피처 (실제 데이터 v5에서 추가)
# 10분 윈도우만으로는 "이 IP가 다시 올지" 예측이 불안정했다. 서버는 과거에 본 IP를
# 기억할 수 있으므로, 실시간에서도 계산 가능한 이력만 피처로 쓴다 (미래 정보 사용 금지).
# ---------------------------------------------------------------------------

HISTORY_FEATURE_NAMES = [
    "hist_windows_24h",      # 최근 24시간 동안 이 IP의 실패 윈도우 수
    "hist_log_fails",        # 이 IP의 누적 실패 수 log(1+x)
    # hist_hours_since_prev(이전 윈도우 이후 경과 시간)는 v6에서 제외:
    # '1시간 이내'가 곧 직전 윈도우의 정답이라, 넣으면 모델이 행동 대신 이전 답을 베낀다
    # (넣으면 CV 0.967 ≈ 단순 관성 규칙 0.957). 관성 효과는 서빙의 차단 TTL이 담당한다.
]
HISTORY_CAP_HOURS = 168.0


class IPHistory:
    """IP별 과거 윈도우 요약 저장소. 학습과 서빙이 같은 클래스를 쓴다."""

    def __init__(self):
        self._store: dict[str, list[tuple[float, float, int]]] = {}  # ip -> [(start, end, n_fail)]

    def features(self, ip: str, now: float) -> dict[str, float]:
        past = [w for w in self._store.get(ip, []) if w[1] <= now]
        last24 = [w for w in past if now - w[1] <= 86400]
        since = min(HISTORY_CAP_HOURS, (now - past[-1][1]) / 3600) if past else HISTORY_CAP_HOURS
        return {
            "hist_windows_24h": float(len(last24)),
            "hist_hours_since_prev": float(since),   # 분석용 (모델 입력에서는 제외)
            "hist_log_fails": math.log1p(sum(w[2] for w in past)),
        }

    def add(self, ip: str, start: float, end: float, n_fail: int) -> None:
        self._store.setdefault(ip, []).append((start, end, n_fail))


def window_bounds(events: Iterable[Mapping]) -> tuple[float, float, int]:
    evs = list(events)
    ts = [_to_epoch(e["ts"]) for e in evs]
    return min(ts), max(ts), sum(e["result"] != "success" for e in evs)
