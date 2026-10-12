"""실제 sshd 로그(Loghub OpenSSH) → 학습용 윈도우 데이터셋(JSONL).

라벨링 (약한 라벨링, IP 단위 · 전체 기간 기준)
  실제 로그에는 정답이 없으므로, **28일 전체 행동**으로 IP를 판정하고
  모델은 그 IP의 **10분 윈도우 하나만 보고** 맞히도록 한다 (= 조기 탐지 문제).

  공격(1): 전체 기간 동안 로그인 성공이 한 번도 없고, 아래 중 하나 이상
           - sshd가 'POSSIBLE BREAK-IN ATTEMPT'(역방향 DNS 불일치)로 경고
           - sshd가 'Too many authentication failures'로 연결을 끊음
           - 전체 실패 RULE_FAILS회 이상
  정상(0): 전체 기간 동안 로그인 성공이 1회 이상
  제외   : 둘 다 아닌 IP (근거 부족 — 라벨을 지어내지 않는다)

사용법:
  python scripts/build_real_dataset.py --log SSH.log --out data/real_windows.jsonl
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from loginguard.sshlog import parse_lines, windows  # noqa: E402

RULE_FAILS = 10


def ip_label(evs, ip, res):
    if any(e["result"] == "success" for e in evs):
        return 0
    n_fail = sum(e["result"] == "fail" for e in evs)
    if ip in res.breakin_ips or ip in res.too_many_ips or n_fail >= RULE_FAILS:
        return 1
    return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--log", required=True)
    ap.add_argument("--out", default="data/real_windows.jsonl")
    ap.add_argument("--start-year", type=int, default=2015)
    a = ap.parse_args()

    with open(a.log, errors="replace") as f:
        res = parse_lines(f, start_year=a.start_year)
    print(f"로그 {res.lines:,}줄 중 로그인 시도 {res.parsed:,}줄 파싱, IP {len(res.events):,}개")

    t0 = min(e["ts"] for evs in res.events.values() for e in evs)
    out = Path(a.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    stats, ip_stats = Counter(), Counter()
    with out.open("w") as f:
        for ip, evs in res.events.items():
            y = ip_label(evs, ip, res)
            ip_stats[y] += 1
            if y is None:
                continue
            for w in windows(evs):
                day = int((w[0]["ts"] - t0) // 86400)
                f.write(json.dumps({"day": day, "ip": ip, "label": y, "events": w}) + "\n")
                stats[y] += 1
    print(f"IP 라벨: 공격 {ip_stats[1]}, 정상 {ip_stats[0]}, 제외 {ip_stats[None]}")
    print(f"윈도우: 공격 {stats[1]:,}, 정상 {stats[0]:,} → {out}")


if __name__ == "__main__":
    main()
