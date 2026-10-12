"""LoginGuard 서빙 API.

흐름: 이벤트 수신 → 피처 추출(학습과 같은 코드) → 규칙 1차 판정 → 회색지대만 모델 판정
     → 차단이면 TTL이 있는 차단 목록에 등록

실행: uvicorn app.main:app --host 0.0.0.0 --port 8000

환경변수
  MODEL_PATH        모델 파일 경로 (기본 models/model.joblib)
  BLOCK_THRESHOLD   차단 판정 확률 임계값 (기본 0.5)
  BLOCK_TTL_SECONDS 차단 유지 시간 (기본 3600 — 오탐으로 영구 차단되는 일 방지)
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

from loginguard.features import extract_features, triage

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

_blocklist: dict[str, float] = {}   # ip -> 만료 시각(epoch)
_lock = Lock()

app = FastAPI(title="LoginGuard", version="0.1.0",
              description="SSH 로그인 기록으로 출발지 IP의 차단 여부를 실시간 판정하는 API")


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
    stage: Literal["allowlist", "rule_allow", "rule_block", "model"]
    attack_probability: float | None
    blocked_until: float | None
    features: dict[str, float]
    model_version: str


def _in_allowlist(ip: str) -> bool:
    addr = ipaddress.ip_address(ip)
    return any(addr in net for net in ALLOWLIST)


def _purge_expired(now: float) -> None:
    for ip in [ip for ip, exp in _blocklist.items() if exp <= now]:
        del _blocklist[ip]


@app.get("/health")
def health():
    return {"status": "ok", "model_version": MODEL_VERSION, "threshold": BLOCK_THRESHOLD}


@app.post("/v1/predict", response_model=PredictResponse)
def predict(req: PredictRequest):
    try:
        ipaddress.ip_address(req.ip)
    except ValueError:
        raise HTTPException(status_code=422, detail=f"올바르지 않은 IP: {req.ip}")

    feats = extract_features([e.model_dump() for e in req.events])
    prob = None

    if _in_allowlist(req.ip):
        stage, decision = "allowlist", "allow"
    else:
        zone = triage(feats)
        if zone == "allow":
            stage, decision = "rule_allow", "allow"
        elif zone == "rule_block":
            stage, decision = "rule_block", "block"
        else:
            x = [[feats[n] for n in _feature_names]]
            prob = float(_model.predict_proba(x)[0][1])
            stage = "model"
            decision = "block" if prob >= BLOCK_THRESHOLD else "allow"

    blocked_until = None
    if decision == "block":
        now = time.time()
        blocked_until = now + BLOCK_TTL_SECONDS
        with _lock:
            _purge_expired(now)
            _blocklist[req.ip] = blocked_until

    return PredictResponse(ip=req.ip, decision=decision, stage=stage,
                           attack_probability=None if prob is None else round(prob, 4),
                           blocked_until=blocked_until, features=feats,
                           model_version=MODEL_VERSION)


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
    with _lock:
        if _blocklist.pop(ip, None) is None:
            raise HTTPException(status_code=404, detail="차단 목록에 없는 IP")
    return {"ip": ip, "unblocked": True}
