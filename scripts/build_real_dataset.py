"""실제 sshd 로그(Loghub OpenSSH) → 학습용 윈도우 데이터셋(JSONL).

문제 정의 (실제 데이터 v4)
  "로그인 실패가 포함된 10분 윈도우를 보고, 그 IP가 다음 1시간 안에 다시 로그인을
   시도할지(= 공격이 계속될지) 예측한다."

  - 라벨은 사람이 붙인 추정치가 아니라 **실제로 그 뒤에 일어난 일**(미래 로그)이다.
  - 차단이 의미 있는 건 그 IP가 다시 올 때뿐이다. 이미 떠난 IP를 막는 건 방화벽 규칙만
    늘린다. 그래서 '다시 올 IP'를 골라 선제 차단하는 것이 서비스 목표다.
  - 실패가 없는 윈도우는 규칙으로 허용(allow)하므로 데이터에서 제외한다.
  - 로그 수집 공백(3일짜리 2곳 등) 직전 윈도우는 '다시 왔는지' 알 수 없으므로 제외한다
    (안 빼면 실제로는 계속 공격했어도 '중단'으로 잘못 라벨링됨).

초기 시도(v4 이전)와 버린 이유
  IP 단위 '공격/정상' 약한 라벨 → 윈도우의 97%가 공격이고 정상은 거의 모두 로그인 성공을
  포함해 규칙만으로 구분됨. 전부 '공격'이라 찍어도 정확도 0.97 → 학습할 의미가 없음.

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

HORIZON_S = 3600   # 다음 1시간
GAP_S = 3600       # 로그가 1시간 이상 비면 '수집 공백'으로 본다


def find_gaps(all_ts, gap_s=GAP_S):
    ts = sorted(all_ts)
    return [(a, b) for a, b in zip(ts, ts[1:]) if b - a >= gap_s]


def censored(end, horizon_s, gaps, last_ts):
    """윈도우 종료 후 horizon 안에 수집 공백이 시작되거나 데이터가 끝나면 정답을 알 수 없다."""
    if end + horizon_s > last_ts:
        return True
    return any(end <= g0 < end + horizon_s for g0, _ in gaps)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--log", required=True)
    ap.add_argument("--out", default="data/real_windows.jsonl")
    ap.add_argument("--start-year", type=int, default=2015)
    ap.add_argument("--horizon-s", type=int, default=HORIZON_S)
    a = ap.parse_args()

    with open(a.log, errors="replace") as f:
        res = parse_lines(f, start_year=a.start_year)
    print(f"로그 {res.lines:,}줄 중 로그인 시도 {res.parsed:,}줄 파싱, IP {len(res.events):,}개")

    all_ts = [e["ts"] for evs in res.events.values() for e in evs]
    gaps, last_ts = find_gaps(all_ts), max(all_ts)
    print(f"수집 공백(1시간 이상) {len(gaps)}곳: " + ", ".join(f"{(b-a)/3600:.0f}h" for a, b in gaps))

    out = Path(a.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    stats = Counter()
    with out.open("w") as f:
        for ip, evs in res.events.items():
            ws = list(windows(evs))
            for i, w in enumerate(ws):
                if not any(e["result"] == "fail" for e in w):
                    continue
                end = w[-1]["ts"]
                if censored(end, a.horizon_s, gaps, last_ts):
                    y = None   # 라벨은 없지만 IP 이력 계산에는 필요하므로 남겨 둔다
                    stats["censored"] += 1
                else:
                    y = int(i + 1 < len(ws) and ws[i + 1][0]["ts"] - end <= a.horizon_s)
                    stats[y] += 1
                f.write(json.dumps({"ts": w[0]["ts"], "ip": ip, "label": y, "events": w}) + "\n")
    total = stats[0] + stats[1]
    print(f"정답을 알 수 없어 제외한 윈도우: {stats['censored']:,}")
    print(f"윈도우 {total:,}개: 계속 공격 {stats[1]:,} ({stats[1]/total:.1%}), 중단 {stats[0]:,} → {out}")


if __name__ == "__main__":
    main()
