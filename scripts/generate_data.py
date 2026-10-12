"""학습용 SSH 로그인 이벤트 합성 데이터 생성기.

실제 운영 로그에는 공격/정상 라벨이 없기 때문에, 실제 sshd(auth.log)에서 관찰되는
패턴을 시나리오로 정의해 '10분 윈도우 × 출발지 IP' 단위 샘플을 만든다.

정확도가 비현실적으로 높게(0.99) 나오지 않도록, 정상과 공격이 겹치는 **어려운 사례**를
일부러 넣었다.
  - 정상인데 공격처럼 보이는 것: 잘못 설정된 자동화 스크립트, 새벽 관리자 접속, NAT 공유 IP
  - 공격인데 정상처럼 보이는 것: low-and-slow, 봇넷 분산 공격(IP당 1~3회), 크리덴셜 스터핑

사용법: python scripts/generate_data.py --out data/login_windows.jsonl --days 30
"""
from __future__ import annotations

import argparse
import json
import random
from pathlib import Path

START_EPOCH = 1788188400  # 2026-09-01 00:00 KST
DAY = 86400

LEGIT_USERS = ["min", "jiwoo", "seojun", "deploy", "backup", "jenkins", "ubuntu", "ec2-user", "app",
               "admin", "git"]  # 실제로 admin/git 계정을 쓰는 서버도 많다
ATTACK_DICT = ["root", "admin", "test", "user", "guest", "oracle", "postgres", "ubuntu",
               "ftp", "pi", "support", "mysql", "git", "administrator", "hadoop", "nagios",
               "www", "minecraft", "steam", "dev", "temp", "zabbix",
               "ec2-user", "ubuntu", "deploy", "jenkins"]  # 클라우드 기본 계정은 봇도 노린다
# 크리덴셜 스터핑: 유출된 이름 목록 — 실제 사용자명과 일부 겹친다
STUFFING_USERS = ["min", "jiwoo", "kim", "lee", "park", "choi", "jung", "seojun", "dev", "app"]
VALID = set(LEGIT_USERS)


def _office_hour(rng):
    return rng.choice([rng.randint(9, 19)] * 4 + [rng.randint(0, 23)])


def _any_hour(rng):
    return rng.randint(0, 23)


def _night_hour(rng):
    return rng.randint(0, 5)


def _times(rng, day, hour, n, mean_gap, jitter):
    """윈도우 시작 시각과 n개의 이벤트 시각(초)을 만든다."""
    t0 = START_EPOCH + day * DAY + hour * 3600 + rng.randint(0, 3000)
    ts, t = [], float(t0)
    for _ in range(n):
        ts.append(t)
        t += max(0.2, rng.gauss(mean_gap, mean_gap * jitter))
    return [x for x in ts if x - ts[0] <= 600] or ts[:1]


def _ev(t, user, ok, method="password"):
    return {"ts": round(t, 2), "user": user, "result": "success" if ok else "fail",
            "invalid_user": user not in VALID, "method": method}


# ---------------- 정상 시나리오 (label 0) ----------------
def legit_key_login(rng, day):
    u = rng.choice(LEGIT_USERS)
    ts = _times(rng, day, _office_hour(rng), rng.randint(1, 3), 120, 0.8)
    m = "publickey" if rng.random() < 0.55 else "password"
    return [_ev(t, u, True, m) for t in ts]


def legit_typo(rng, day):
    u = rng.choice(LEGIT_USERS)
    nf = rng.randint(1, 5)
    ts = _times(rng, day, _office_hour(rng), nf + 1, rng.uniform(4, 20), 0.6)
    typo = u[:-1] if rng.random() < 0.3 else u          # 계정명 자체를 잘못 친 경우
    evs = [_ev(t, typo if i == 0 else u, False) for i, t in enumerate(ts[:-1])] + [_ev(ts[-1], u, True)]
    if rng.random() < 0.3:          # 끝내 성공하지 못하고 포기
        evs[-1]["result"] = "fail"
    return evs


def legit_single_fail(rng, day):
    u = rng.choice(LEGIT_USERS + ["mni", "jiwo", "Min"])  # 오타 계정명 포함
    ts = _times(rng, day, _any_hour(rng), rng.randint(1, 2), 30, 0.5)
    return [_ev(t, u, False, rng.choice(["password", "publickey"])) for t in ts]


def legit_broken_automation(rng, day):
    """비밀번호/키가 바뀐 줄 모르는 백업·배포 스크립트 — 기계적으로 일정한 실패 반복."""
    u = rng.choice(["deploy", "backup", "jenkins", "app"])
    ts = _times(rng, day, _any_hour(rng), rng.randint(5, 40), rng.choice([10, 15, 30, 60]), 0.05)
    return [_ev(t, u, False, rng.choice(["password", "publickey"])) for t in ts]


def legit_night_admin(rng, day):
    u = rng.choice(["ubuntu", "ec2-user", "min"])
    nf = rng.choice([0, 0, 1, 2, 3])
    ts = _times(rng, day, _night_hour(rng), nf + 1, 8, 0.6)
    m = rng.choice(["publickey", "password"])
    return [_ev(t, u, False, m) for t in ts[:-1]] + [_ev(ts[-1], u, True, m)]


def legit_shared_nat(rng, day):
    """학교·회사 NAT 뒤 여러 사용자가 같은 공인 IP로 접속."""
    users = rng.sample(LEGIT_USERS, rng.randint(2, 4))
    ts = _times(rng, day, _office_hour(rng), rng.randint(3, 9), 50, 1.0)
    return [_ev(t, rng.choice(users), rng.random() > 0.25,
                rng.choice(["publickey", "password"])) for t in ts]


# ---------------- 공격 시나리오 (label 1) ----------------
def atk_brute_force(rng, day):
    u = rng.choice(["root", "admin", "ubuntu"])
    ts = _times(rng, day, _any_hour(rng), rng.randint(20, 150), rng.uniform(1, 6), 0.3)
    return [_ev(t, u if rng.random() < 0.7 else rng.choice(ATTACK_DICT), False) for t in ts]


def atk_dictionary(rng, day):
    ts = _times(rng, day, _any_hour(rng), rng.randint(8, 60), rng.uniform(2, 15), 0.5)
    return [_ev(t, rng.choice(ATTACK_DICT), False) for t in ts]


def atk_low_and_slow(rng, day):
    users = rng.sample(ATTACK_DICT, rng.randint(1, 2))
    ts = _times(rng, day, _any_hour(rng), rng.randint(2, 6), rng.uniform(60, 200), 0.6)
    return [_ev(t, rng.choice(users), False) for t in ts]


def atk_credential_stuffing(rng, day):
    ts = _times(rng, day, _any_hour(rng), rng.randint(3, 15), rng.uniform(5, 40), 0.7)
    evs = [_ev(t, rng.choice(STUFFING_USERS), False) for t in ts]
    if rng.random() < 0.25:          # 유출 비밀번호가 맞아떨어져 침입 성공
        evs[-1]["result"] = "success"
    return evs


def atk_botnet_member(rng, day):
    """봇넷이 IP를 분산해 IP당 1~3회만 시도 — 단일 IP 관점에서는 가장 어려운 공격."""
    ts = _times(rng, day, _any_hour(rng), rng.randint(1, 3), rng.uniform(20, 90), 0.5)
    return [_ev(t, rng.choice(ATTACK_DICT + STUFFING_USERS[:3]), False) for t in ts]


SCENARIOS = [
    # (함수, 라벨, 가중치)
    (legit_key_login, 0, 22), (legit_typo, 0, 12), (legit_single_fail, 0, 6),
    (legit_broken_automation, 0, 4), (legit_night_admin, 0, 4), (legit_shared_nat, 0, 4),
    (atk_brute_force, 1, 12), (atk_dictionary, 1, 10), (atk_low_and_slow, 1, 8),
    (atk_credential_stuffing, 1, 8), (atk_botnet_member, 1, 10),
]


def generate(days: int, per_day: int, seed: int, label_noise: float):
    rng = random.Random(seed)
    funcs, labels, weights = zip(*SCENARIOS)
    rows = []
    for day in range(days):
        for _ in range(per_day):
            i = rng.choices(range(len(funcs)), weights=weights)[0]
            events = funcs[i](rng, day)
            y = labels[i]
            if rng.random() < label_noise:   # 보안 담당자 라벨링 실수 반영
                y = 1 - y
            rows.append({"day": day, "scenario": funcs[i].__name__, "label": y, "events": events})
    return rows


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="data/login_windows.jsonl")
    ap.add_argument("--days", type=int, default=30)
    ap.add_argument("--per-day", type=int, default=400)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--label-noise", type=float, default=0.02)
    a = ap.parse_args()
    rows = generate(a.days, a.per_day, a.seed, a.label_noise)
    out = Path(a.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w") as f:
        for r in rows:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
    pos = sum(r["label"] for r in rows)
    print(f"{len(rows)}개 윈도우 생성 → {out} (공격 {pos}, 정상 {len(rows) - pos})")


if __name__ == "__main__":
    main()
