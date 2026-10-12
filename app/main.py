"""LoginGuard 서빙 API.

서비스 정의: IP의 10분 로그인 기록(성공·실패 모두)을 받아, 그 IP가 다음 1시간 안에 다시 와서
            로그인 실패를 일으킬지(= 공격이 계속될지) 예측하고, 계속 공격할 IP를 차단 목록
            (TTL 1시간)에 올린다. 공격 이력이 있는 IP의 로그인 성공은 침입 의심 경보로 알린다.

흐름: 이벤트 수신 → 10분 윈도우로 자르기 → 피처 추출(학습과 같은 코드)
     → 허용 목록/안전망 규칙 → 모델 판정 → 침입 의심 경보 → 차단 목록 등록 → IP 이력 갱신

호출 방법: 로그 수집기가 IP별 10분 윈도우가 끝날 때마다 한 번 호출한다
          (학습 데이터와 같은 tumbling window. 같은 이벤트를 겹쳐 보내면 이력이 중복 집계됨).

실행: uvicorn app.main:app --host 0.0.0.0 --port 8000

환경변수
  MODEL_PATH        모델 파일 경로 (기본 models/model.joblib)
  BLOCK_THRESHOLD   차단 판정 확률 임계값 (기본 0.5)
  BLOCK_TTL_SECONDS 차단 유지 시간 (기본 3600 — 예측 기간 1시간과 같게)
  ALLOWLIST         항상 허용할 IP/CIDR, 쉼표 구분 (예: "10.0.0.0/8,203.0.113.7")
"""
from __future__ import annotations

import hashlib
import ipaddress
import os
import time
from pathlib import Path
from threading import Lock
from typing import Literal

import joblib
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from loginguard.features import (WINDOW_SECONDS, IPHistory, _to_epoch, extract_features,
                                 success_alert, triage, window_bounds)

ROOT = Path(__file__).resolve().parents[1]
MODEL_PATH = Path(os.getenv("MODEL_PATH", ROOT / "models" / "model.joblib"))
BLOCK_THRESHOLD = float(os.getenv("BLOCK_THRESHOLD", "0.5"))
BLOCK_TTL_SECONDS = int(os.getenv("BLOCK_TTL_SECONDS", "3600"))
ALLOWLIST = [ipaddress.ip_network(x.strip(), strict=False)
             for x in os.getenv("ALLOWLIST", "").split(",") if x.strip()]

_bundle = joblib.load(MODEL_PATH)
_model = _bundle["model"]
_feature_names: list[str] = _bundle["feature_names"]
MODEL_VERSION = f"{_bundle['model_name']}@{hashlib.sha256(MODEL_PATH.read_bytes()).hexdigest()[:12]}"

# 주의: 아래 두 저장소는 프로세스 메모리에 있다. 여러 worker/Pod로 늘리면 Redis 등 공유 저장소 필요.
_blocklist: dict[str, float] = {}   # ip -> 만료 시각(epoch)
_history = IPHistory()
_lock = Lock()

app = FastAPI(title="LoginGuard", version="0.3.0",
              description="SSH 로그인 기록으로 '1시간 안에 다시 공격할 IP'를 예측해 차단하는 API")


class LoginEvent(BaseModel):
    ts: str | float = Field(..., description="ISO8601 문자열 또는 epoch 초")
    user: str
    result: Literal["success", "fail"]
    invalid_user: bool = False
    method: Literal["password", "publickey"] = "password"


class PredictRequest(BaseModel):
    ip: str = Field(..., examples=["198.51.100.23"])
    events: list[LoginEvent] = Field(..., min_length=1, max_length=5000,
                                     description="해당 IP의 최근 10분 로그인 이벤트")


class PredictResponse(BaseModel):
    ip: str
    decision: Literal["allow", "block"]
    stage: Literal["allowlist", "rule_block", "model"]
    continue_probability: float | None = Field(None, description="1시간 안에 다시 와서 실패를 일으킬 확률")
    alert: Literal["possible_compromise"] | None = Field(
        None, description="공격 이력(누적 실패 20회 이상)이 있는 IP가 로그인에 성공함 — 담당자 확인 필요")
    blocked_until: float | None
    dropped_old_events: int = Field(0, description="10분 윈도우 밖이라 버린 이벤트 수")
    features: dict[str, float]
    model_version: str


def _normalize_ip(ip: str) -> str:
    try:
        return str(ipaddress.ip_address(ip))
    except ValueError:
        raise HTTPException(status_code=422, detail=f"올바르지 않은 IP: {ip}")


def _in_allowlist(ip: str) -> bool:
    addr = ipaddress.ip_address(ip)
    return any(addr in net for net in ALLOWLIST)


def _purge_expired(now: float) -> None:
    for ip in [ip for ip, exp in _blocklist.items() if exp <= now]:
        del _blocklist[ip]


def _trim_to_window(events: list[dict]) -> tuple[list[dict], int]:
    """학습과 같은 10분 윈도우만 남긴다 (가장 최근 이벤트 기준)."""
    latest = max(_to_epoch(e["ts"]) for e in events)
    kept = [e for e in events if latest - _to_epoch(e["ts"]) < WINDOW_SECONDS]
    return kept, len(events) - len(kept)


@app.get("/health")
def health():
    return {"status": "ok", "model_version": MODEL_VERSION, "threshold": BLOCK_THRESHOLD,
            "features": _feature_names}


@app.post("/v1/predict", response_model=PredictResponse)
def predict(req: PredictRequest):
    ip = _normalize_ip(req.ip)
    events, dropped = _trim_to_window([e.model_dump() for e in req.events])
    start, end, n_fail = window_bounds(events)

    feats = extract_features(events)
    with _lock:
        feats.update(_history.features(ip, start))
    prob = None

    if _in_allowlist(ip):
        stage, decision = "allowlist", "allow"
    else:
        zone = triage(feats)
        if zone == "rule_block":
            stage, decision = "rule_block", "block"   # 10분 내 20회 이상 실패: 안전망으로 즉시 차단
        else:
            x = [[feats[n] for n in _feature_names]]
            prob = float(_model.predict_proba(x)[0][1])
            stage = "model"
            decision = "block" if prob >= BLOCK_THRESHOLD else "allow"

    alert = "possible_compromise" if success_alert(feats) else None

    now = time.time()
    blocked_until = None
    with _lock:
        if n_fail > 0:
            _history.add(ip, start, end, n_fail)
        if decision == "block":
            blocked_until = now + BLOCK_TTL_SECONDS
            _purge_expired(now)
            _blocklist[ip] = blocked_until

    return PredictResponse(ip=ip, decision=decision, stage=stage,
                           continue_probability=None if prob is None else round(prob, 4), alert=alert,
                           blocked_until=blocked_until, dropped_old_events=dropped,
                           features=feats, model_version=MODEL_VERSION)


@app.get("/v1/blocklist")
def blocklist():
    """방화벽 에이전트(iptables/보안그룹 동기화)가 주기적으로 가져갈 현재 차단 목록."""
    now = time.time()
    with _lock:
        _purge_expired(now)
        return {"count": len(_blocklist),
                "items": [{"ip": ip, "expires_in_s": int(exp - now)}
                          for ip, exp in sorted(_blocklist.items())]}


@app.delete("/v1/blocklist/{ip}")
def unblock(ip: str):
    """오탐 시 관리자가 수동 해제."""
    ip = _normalize_ip(ip)
    with _lock:
        if _blocklist.pop(ip, None) is None:
            raise HTTPException(status_code=404, detail="차단 목록에 없는 IP")
    return {"ip": ip, "unblocked": True}
