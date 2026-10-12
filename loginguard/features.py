"""로그인 이벤트 → 모델 입력 피처 변환.

학습(scripts/train.py)과 서빙(app/main.py)이 **같은 함수**를 쓰도록 이 모듈 하나로 모아 둔다.
(training-serving skew 방지)

입력 단위: 한 출발지 IP가 최근 10분(WINDOW_SECONDS) 동안 남긴 SSH 로그인 이벤트 목록.
"""
from __future__ import annotations

from datetime import datetime, timezone
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


RULE_BLOCK_FAILS = 20  # 10분 내 실패 20회 이상 → 모델 없이 즉시 차단 (fail2ban류 규칙)


def triage(feats: Mapping[str, float]) -> str:
    """규칙으로 판정이 끝나는 구간과 모델이 판단할 회색지대를 나눈다.

    - "allow": 실패가 한 번도 없음 → 차단할 이유 없음
    - "rule_block": 실패가 RULE_BLOCK_FAILS회 이상 → 명백한 무차별 대입
    - "model": 그 사이 회색지대 → ML 모델이 판정
    """
    n_fail = round(feats["fail_ratio"] * feats["n_attempts"])
    if n_fail == 0:
        return "allow"
    if n_fail >= RULE_BLOCK_FAILS:
        return "rule_block"
    return "model"


def to_vector(feats: Mapping[str, float]) -> list[float]:
    return [float(feats[name]) for name in FEATURE_NAMES]
