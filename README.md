# LoginGuard — SSH 로그인 기록으로 "계속 공격할 IP"를 예측해 차단하는 API

## 1. 서비스 정의 (한 문장)

> **IP의 10분 SSH 로그인 기록(성공·실패 모두)을 받아, 그 IP가 다음 1시간 안에 다시 와서 로그인 실패를 일으킬지 예측하고, 계속 공격할 IP를 차단 목록에 올리는 API.**

- **예측 단위**: (출발지 IP × 10분 윈도우) 1건 — 성공만 있는 접속도 포함
- **출력**: `allow` / `block` + 1시간 내 재공격 확률 + 침입 의심 경보(`alert`)
- **왜 이 정의인가**: 차단은 그 IP가 다시 올 때만 의미가 있다. 이미 떠난 IP를 막으면 방화벽 규칙만 늘어난다.
- **사용 흐름**: 로그 수집기가 IP별 10분 윈도우가 끝날 때마다 `/v1/predict` 호출 → 방화벽 에이전트가 `/v1/blocklist`를 가져가 iptables·보안그룹에 반영

## 2. 데이터 — 실제 sshd 로그

**[Loghub OpenSSH](https://github.com/logpai/loghub/tree/master/OpenSSH)**: 연구실 서버(LabSZ)의 실제 sshd 로그, 2015-12-10 ~ 2016-01-07, 655,146줄

| 단계 | 결과 |
|---|---|
| 파싱 (`loginguard/sshlog.py`) | 로그인 시도 관련 198,012줄, IP 1,044개 |
| 10분 윈도우 (성공·실패 모두) | 5,319개 (성공 포함 146개 — 모두 연구실 사용자 9명의 정상 접속) |
| 라벨을 알 수 없어 제외 | 47개 (로그 수집 공백 직전·데이터 끝) |
| **학습/평가** | **5,272개 — 계속 공격 42.7%, 중단 57.3%** |

**라벨**: 사람이 붙인 추정이 아니라 **실제로 일어난 일**이다. 윈도우가 끝난 뒤 1시간 안에 같은 IP가 다시 와서 **로그인 실패**를 일으켰으면 1, 아니면 0.
("다시 오기만 하면 1"로 하면 정상 사용자의 재접속도 공격으로 세게 된다.)

데이터를 받아 다시 만들려면:
```bash
# https://zenodo.org/records/8196385/files/SSH.tar.gz 다운로드 후 압축 해제
python scripts/build_real_dataset.py --log SSH.log --out data/real_windows.jsonl
```

## 3. 피처

| 피처 | 의미 |
|---|---|
| `n_attempts`, `fail_ratio` | 10분 내 시도 수, 실패 비율 |
| `n_unique_users`, `invalid_user_ratio`, `privileged_user_ratio` | 계정 바꿔 가며 시도, 없는 계정, root/admin 등 사전 계정 |
| `password_ratio` | 비밀번호 인증 비율 |
| `mean_interval_s`, `interval_cv` | 시도 간격과 그 규칙성(자동화 도구 여부) |
| `success_after_fails` | 실패 3회 이상 뒤 성공 |
| `hist_windows_24h` | 이 IP가 최근 24시간 동안 실패 윈도우를 남긴 횟수 |
| `hist_log_fails` | 이 IP의 누적 실패 수 (log) |

실패 0회 윈도우도 이 피처들로 판단한다. 예: 성공만 있으면 `fail_ratio`=0, 공격 이력이 있으면 `hist_*`가 큼.

- 윈도우 피처와 IP 이력은 `loginguard/features.py` 하나에서 계산한다 → 학습과 서빙이 같은 코드 사용
- 실제 로그 전체를 API에 재생해 학습 파이프라인과 비교: **피처 불일치 0건 / 5,319 윈도우**
- 이력은 **과거 윈도우만** 사용 (미래 정보 없음)

## 4. 모델 실험 기록

평가는 **시간 순 롤링 교차검증**(기간을 5구간으로 나눠, 앞 k구간으로 학습 → 다음 구간 테스트, 4폴드)으로 한다. 무작위 분할을 하면 미래 데이터가 학습에 섞인다.

| 버전 | 데이터 / 정의 | 결과 | 판단 |
|---|---|---|---|
| v1~v3 | 합성 데이터, 공격/정상 분류 | 0.976 → 0.950 | 합성 데이터라 실제 성능을 보장 못 함 → 실제 데이터로 전환 |
| v4-a | 실제, IP별 공격/정상 약한 라벨 | 윈도우의 97%가 공격 | 전부 "공격"이라 찍어도 0.97 → 학습 의미 없음, **문제 재정의** |
| v4-b | 실제, "1시간 안에 다시 오는가", 윈도우 피처만, 단일 분할 | 테스트 0.954 / 학습 0.77 | 테스트가 학습보다 높음 → 분할이 우연히 쉬웠음 |
| v4-c | 같은 정의, 롤링 CV | 0.80 ± 0.16 | 폴드별 0.62~0.95로 불안정 |
| v5 | + 수집 공백 라벨 제외, + IP 이력 피처 3개 | 0.967 ± 0.010 | 너무 높음 → 원인 분석 |
| v5 분석 | "직전 1시간 안에 왔으면 또 온다" 규칙 | 0.957 | 모델이 이 규칙을 베낀 것. `hist_hours_since_prev < 1h`는 **직전 윈도우의 정답 그 자체** |
| v5 분석 | 처음 보는 IP만 예측하도록 재정의 | 양성 4~18% | 모델이 "전부 아니다" 기준선보다 낮음 → 기각 |
| v6 | 직전 정답을 담은 피처 제거. 관성 효과는 서빙의 **차단 TTL 1시간**이 담당 | 0.923 ± 0.030 | 실패만 보는 구조의 빈틈 발견 |
| **v7 최종** | **성공만 있는 윈도우도 포함**, 라벨을 "다시 와서 실패를 일으키는가"로 수정, 실패 0회 자동 통과 규칙 삭제 | **0.922 ± 0.034** | 채택 |

**최종 모델: 로지스틱 회귀** (피처 11개)

롤링 교차검증 정확도

| 모델 | 평균 ± 표준편차 | 폴드 1~4 |
|---|---|---|
| 기준선: 다수 클래스 | 0.575 ± 0.161 | 0.670 / 0.786 / 0.382 / 0.461 |
| 기준선: 10분 내 실패 20회 이상 | 0.816 ± 0.089 | 0.711 / 0.749 / 0.925 / 0.880 |
| **로지스틱 회귀** | **0.922 ± 0.034** | 0.865 / 0.931 / 0.953 / 0.941 |
| 랜덤 포레스트 | 0.905 ± 0.069 | 0.787 / 0.930 / 0.954 / 0.950 |
| HistGradientBoosting | 0.917 ± 0.054 | 0.825 / 0.939 / 0.949 / 0.956 |

홀드아웃 (마지막 20% 기간, 1,055건)

| Accuracy | Balanced Acc | Precision | Recall | F1 | Train Acc |
|---|---|---|---|---|---|
| 0.941 | 0.943 | 0.963 | 0.926 | 0.944 | 0.944 |

성공 접속까지 보도록 바꾼 뒤의 세부 지표

| 지표 | 값 |
|---|---|
| 성공이 포함된 윈도우 정확도 (홀드아웃) | 1.000 (56건) |
| 실패만 있는 윈도우 정확도 (홀드아웃) | 0.938 (999건) |
| **정상 사용자 윈도우를 차단으로 판정한 비율** (롤링 예측) | **0.0%** (114건) |
| 침입 의심 경보 오경보 (정상 사용자 성공 146건) | **0건** |

- 학습·홀드아웃 정확도가 비슷해 과적합 없음
- 가장 단순한 모델이 이겼고, 폴드 간 편차도 가장 작음

**한계**
- **실패 없이 한 번에 성공한 침입**(유출된 비밀번호·키)은 이 데이터에 정답 사례가 없어 학습하지 못했다. 공격 이력이 있는 IP의 성공은 경보로 잡지만, 공격 이력 없는 새 IP의 첫 성공은 잡지 못한다 → 후속 과제: 정상 로그인 이력을 쌓아 이상 탐지(새 IP·국가·시간대)를 붙인다
- 서버 1대, 28일치 데이터 → 다른 서버·다른 시기에서는 재검증 필요
- 진행 중인 공격(직전 1시간 내 활동)은 "또 온다" 규칙이 0.957로 더 정확하다. 서비스에서는 그 역할을 차단 TTL이 맡는다는 전제로 설계했다
- 규칙·모델을 합친 서비스 전체 정확도는 0.899다. "실패 20회 이상 즉시 차단" 안전망이 일부 이미 끝난 공격도 차단하기 때문이다(보안상 의도된 보수적 선택)

## 5. 판정 흐름

```
이벤트 수신 → 10분 밖 이벤트 버림 → 피처 + IP 이력 → ALLOWLIST? ─예→ allow
                                                       │아니오
                                                       ├ 실패 20회 이상  → block (rule_block, 안전망)
                                                       └ 그 외(성공만 있어도) → 모델: 재공격 확률 ≥ 0.5 → block
성공이 있고 이 IP의 누적 실패가 20회 이상 → alert: possible_compromise (침입 의심, 담당자 확인)
block → 차단 목록 등록 (TTL 1시간 = 예측 기간과 동일, 관리자 수동 해제 가능)
```

## 6. API

| 메서드 | 경로 | 설명 |
|---|---|---|
| GET | `/health` | 상태, 모델 버전, 임계값, 사용 피처 |
| POST | `/v1/predict` | IP + 10분 이벤트 → 재공격 확률과 차단 판정 |
| GET | `/v1/blocklist` | 현재 차단 목록 (방화벽 에이전트용) |
| DELETE | `/v1/blocklist/{ip}` | 오탐 수동 해제 |

요청 예시:
```bash
curl -X POST localhost:8000/v1/predict -H 'content-type: application/json' -d '{
  "ip": "198.51.100.77",
  "events": [
    {"ts": "2026-10-12T03:00:00Z", "user": "oracle",   "result": "fail", "invalid_user": true},
    {"ts": "2026-10-12T03:00:40Z", "user": "postgres", "result": "fail", "invalid_user": true},
    {"ts": "2026-10-12T03:01:30Z", "user": "root",     "result": "fail"}
  ]}'
```
응답 필드: `decision`, `stage`, `continue_probability`, `alert`, `blocked_until`, `dropped_old_events`, `features`, `model_version`

환경변수: `BLOCK_THRESHOLD`(0.5), `BLOCK_TTL_SECONDS`(3600), `ALLOWLIST`(예: `10.0.0.0/8`), `MODEL_PATH`

## 7. 실행

```bash
pip install -r requirements.txt
python scripts/build_real_dataset.py --log SSH.log   # data/real_windows.jsonl
python scripts/train_real.py                         # models/model.joblib, models/metrics.json
uvicorn app.main:app --port 8000                     # http://localhost:8000/docs
pytest                                               # 25개
```

Docker:
```bash
docker build -t loginguard .
docker run -p 8000:8000 -e ALLOWLIST=10.0.0.0/8 loginguard
```

## 8. 구조
```
loginguard/sshlog.py        실제 sshd 로그 파서, 10분 윈도우 분할
loginguard/features.py      윈도우 피처 + IP 이력 + 규칙 triage (학습·서빙 공용)
scripts/build_real_dataset.py  실제 로그 → 라벨링된 윈도우 데이터셋
scripts/train_real.py       롤링 CV로 모델 비교·최종 학습 (최종 모델)
scripts/generate_data.py, scripts/train_synthetic.py   v1~v3 합성 데이터 실험 (기록용)
app/main.py                 FastAPI 서빙
models/                     학습된 모델, 지표
tests/                      API(가짜 모델 주입) · 파서 · 피처 · 모델 품질 테스트
```

## 9. 출처
Jieming Zhu et al., *Loghub: A Large Collection of System Log Datasets for AI-driven Log Analytics*, ISSRE 2023.
