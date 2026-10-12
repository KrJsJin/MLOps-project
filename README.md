# LoginGuard — SSH 로그인 기록 기반 비정상 접근 실시간 차단 API

## 1. 서비스 정의 (한 문장)

> **클라우드 서버에 SSH 로그인을 시도한 출발지 IP의 최근 10분 기록을 받아, 그 IP를 지금 차단해야 하는지를 판정하고 차단 목록에 올리는 API.**

- **예측 단위**: (출발지 IP × 최근 10분 윈도우) 1건
- **출력**: `allow` / `block` + 공격 확률
- **사용자**: 서버의 로그 수집기(Fluent Bit 등)가 호출하고, 방화벽 에이전트가 `/v1/blocklist`를 가져가 iptables·보안그룹에 반영

## 2. 피처와 라벨

**라벨**: 해당 윈도우가 공격(1)인지 정상(0)인지

| 피처 | 의미 | 왜 필요한가 |
|---|---|---|
| `n_attempts` | 10분 내 시도 횟수 | 시도량 |
| `fail_ratio` | 실패 비율 | 비밀번호를 모르는 공격자는 계속 실패 |
| `n_unique_users` | 서로 다른 계정 수 | 사전 공격은 계정명을 바꿔 가며 시도 |
| `invalid_user_ratio` | 존재하지 않는 계정 비율 | sshd `Invalid user` 로그 |
| `privileged_user_ratio` | root/admin 등 사전 계정 비율 | 봇이 노리는 계정 |
| `password_ratio` | 비밀번호 인증 비율 | 정상 사용자는 공개키를 많이 씀 |
| `mean_interval_s` | 시도 간 평균 간격 | 도구는 빠르거나(brute force) 일부러 느림(low-and-slow) |
| `interval_cv` | 간격 변동계수 | 기계적으로 일정한 간격 = 자동화 |
| `success_after_fails` | 실패 3회 이상 뒤 성공 | 크리덴셜 스터핑 성공 = 침입 신호 |

피처 계산은 `loginguard/features.py` 하나로 모아 **학습과 서빙이 같은 코드**를 쓰도록 했다(training-serving skew 방지).

### 데이터
실제 운영 로그에는 라벨이 없으므로, sshd에서 관찰되는 패턴을 시나리오로 정의해 합성했다(`scripts/generate_data.py`, 30일 × 하루 400윈도우, 라벨 노이즈 2%).
정상과 공격이 겹치는 어려운 사례를 일부러 넣었다.

- 정상인데 공격처럼 보임: 비밀번호가 바뀐 백업 스크립트의 반복 실패, 새벽 관리자 접속, NAT 공유 IP
- 공격인데 정상처럼 보임: low-and-slow, 봇넷 분산 공격(IP당 1~3회), 크리덴셜 스터핑

## 3. 모델 실험 기록

평가: **시간 순 분할**(앞 24일 학습 / 뒤 6일 테스트). 무작위 분할을 하면 미래 패턴이 학습에 섞인다.

| 버전 | 변경 | 최고 테스트 정확도 | 판단 |
|---|---|---|---|
| v1 | 전체 윈도우, 피처 10개 | 0.976 | **과도하게 높음** → 피처 점검 |
| v1-ablation | 의심 피처(`invalid_user_ratio`, `privileged_user_ratio`, `password_ratio`)를 하나씩·함께 제거 | 0.95~0.976 | 피처를 빼도 높음 → 피처가 아니라 **데이터·문제 정의** 문제 |
| v2 | 합성 데이터 현실화: 정상 계정·공격 사전 겹침(`ubuntu`, `ec2-user`, `admin` 등), 정상 로그인 비밀번호 인증 혼재, 계정명 오타 | 0.969 | 여전히 높음 → 원인 분석 |
| v3 | **문제 재정의**: 실패 0회(24%)와 10분 내 실패 20회 이상(22%)은 규칙으로 판정하고, 그 사이 **회색지대만 모델이 판정** | 0.950 | 쉬운 케이스가 정확도를 부풀리던 것을 제거 |
| **v3 최종** | 기여도가 거의 0인 `night_ratio` 제거(permutation importance 0.0006) | **0.950** | 채택 |

**최종 모델 (Random Forest, 회색지대 테스트 1,270건)**

| Accuracy | Precision | Recall | F1 | Train Acc |
|---|---|---|---|---|
| 0.950 | 0.958 | 0.951 | 0.954 | 0.949 |

- 학습·테스트 정확도 차이가 거의 없어 과적합은 보이지 않음
- 피처 기여도가 한 피처에 몰리지 않음 (상위: `invalid_user_ratio` 0.11, `mean_interval_s` 0.10, `password_ratio` 0.09)
- 가장 많이 틀리는 유형: 봇넷 분산 공격(0.90)과 정상 사용자의 단발성 실패(0.89) — 1~2회 시도만으로는 원리적으로 구분이 어려운 사례
- 비교: 로지스틱 회귀 0.918, HistGradientBoosting 0.949

> 한계: 합성 데이터라 실제 로그에서는 정확도가 더 낮을 수 있다. 다음 단계로 클라우드 VM에 SSH를 열어 실제 공격 로그를 모아 재평가할 계획.

## 4. 판정 흐름

```
이벤트 수신 → 피처 추출 → ALLOWLIST? ─예→ allow
                           │아니오
                           ├ 실패 0회        → allow   (rule_allow)
                           ├ 실패 20회 이상   → block   (rule_block)
                           └ 회색지대        → 모델 확률 ≥ 0.5 → block
block → 차단 목록 등록 (TTL 1시간 후 자동 해제, 관리자 수동 해제 가능)
```

## 5. API

| 메서드 | 경로 | 설명 |
|---|---|---|
| GET | `/health` | 상태, 모델 버전, 임계값 |
| POST | `/v1/predict` | IP + 최근 10분 이벤트 → 차단 판정 |
| GET | `/v1/blocklist` | 현재 차단 목록(방화벽 에이전트용) |
| DELETE | `/v1/blocklist/{ip}` | 오탐 수동 해제 |

요청 예시:
```bash
curl -X POST localhost:8000/v1/predict -H 'content-type: application/json' -d '{
  "ip": "198.51.100.77",
  "events": [
    {"ts": "2026-10-12T03:00:00Z", "user": "oracle",   "result": "fail", "invalid_user": true},
    {"ts": "2026-10-12T03:01:40Z", "user": "oracle",   "result": "fail", "invalid_user": true},
    {"ts": "2026-10-12T03:03:30Z", "user": "postgres", "result": "fail", "invalid_user": true}
  ]}'
```
응답 요약: `"decision": "block", "stage": "model", "attack_probability": 0.995` (3회뿐이라 규칙으로는 못 잡는 low-and-slow 공격)

환경변수: `BLOCK_THRESHOLD`(0.5), `BLOCK_TTL_SECONDS`(3600), `ALLOWLIST`(예: `10.0.0.0/8`), `MODEL_PATH`

## 6. 실행

```bash
pip install -r requirements.txt
python scripts/generate_data.py          # data/login_windows.jsonl 생성
python scripts/train.py                  # models/model.joblib, models/metrics.json
uvicorn app.main:app --port 8000         # http://localhost:8000/docs 에서 Swagger 확인
pytest                                   # 테스트 13개
```

Docker:
```bash
docker build -t loginguard .
docker run -p 8000:8000 -e ALLOWLIST=10.0.0.0/8 loginguard
```

## 7. 구조
```
loginguard/features.py   피처 추출 + 규칙 triage (학습·서빙 공용)
scripts/generate_data.py 합성 데이터 생성
scripts/train.py         모델 비교·학습·저장
app/main.py              FastAPI 서빙
models/                  학습된 모델, 지표
tests/                   API·피처 테스트
```
