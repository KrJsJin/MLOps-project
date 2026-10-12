"""sshd 로그(auth.log 형식) → 로그인 시도 이벤트 파서.

지원하는 줄 (Loghub OpenSSH 데이터셋에서 확인한 형식):
  Accepted password|publickey for <user> from <ip> port <p> ssh2
  Failed password for [invalid user ]<user> from <ip> port <p> ssh2
  Failed none for invalid user <user> from <ip> port <p> ssh2
  message repeated <N> times: [ Failed password for <user> from <ip> port <p> ssh2]
  reverse mapping checking getaddrinfo for <host> [<ip>] failed - POSSIBLE BREAK-IN ATTEMPT!
  Disconnecting: Too many authentication failures for <user> [preauth]   (IP 없음 → pid로 연결)

syslog 형식에는 연도가 없으므로 시작 연도를 받고, 월이 거꾸로 가면(12월 → 1월) 연도를 올린다.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Iterable, Iterator

_HEAD = re.compile(r"^(?P<mon>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d\d:\d\d:\d\d)\s+\S+\s+sshd\[(?P<pid>\d+)\]:\s+(?P<msg>.*)$")
_ACCEPTED = re.compile(r"^Accepted (?P<method>\w+) for (?P<user>\S+) from (?P<ip>[\d.:a-fA-F]+) port")
_FAILED = re.compile(r"^Failed (?P<method>\w+) for (?P<inv>invalid user )?(?P<user>\S*) from (?P<ip>[\d.:a-fA-F]+) port")
_REPEATED = re.compile(r"^message repeated (?P<n>\d+) times: \[ Failed (?P<method>\w+) for (?P<inv>invalid user )?(?P<user>\S*) from (?P<ip>[\d.:a-fA-F]+) port")
_BREAKIN = re.compile(r"\[(?P<ip>[\d.]+)\] failed - POSSIBLE BREAK-IN ATTEMPT")
_TOO_MANY = re.compile(r"^Disconnecting: Too many authentication failures")

_MONTHS = {m: i for i, m in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], 1)}

KST = timezone(timedelta(hours=9))


@dataclass
class ParseResult:
    events: dict[str, list[dict]] = field(default_factory=dict)  # ip -> 로그인 시도 이벤트
    breakin_ips: set[str] = field(default_factory=set)           # 역방향 DNS 불일치 경고 IP
    too_many_ips: set[str] = field(default_factory=set)          # '인증 실패 과다'로 끊긴 IP
    lines: int = 0
    parsed: int = 0


def _method(m: str) -> str:
    return "publickey" if m == "publickey" else "password"   # none/keyboard-interactive → password


def parse_lines(lines: Iterable[str], start_year: int = 2015, tz=KST) -> ParseResult:
    res = ParseResult()
    year, last_month = start_year, None
    pid_ip: dict[str, str] = {}

    for raw in lines:
        res.lines += 1
        h = _HEAD.match(raw.rstrip("\n"))
        if not h:
            continue
        month = _MONTHS.get(h["mon"])
        if month is None:
            continue
        if last_month is not None and month < last_month:
            year += 1
        last_month = month
        hh, mm, ss = map(int, h["time"].split(":"))
        ts = datetime(year, month, int(h["day"]), hh, mm, ss, tzinfo=tz).timestamp()
        msg, pid = h["msg"], h["pid"]

        if m := _ACCEPTED.match(msg):
            evs = [dict(ts=ts, user=m["user"], result="success", invalid_user=False,
                        method=_method(m["method"]))]
        elif m := _REPEATED.match(msg):
            evs = [dict(ts=ts, user=m["user"], result="fail", invalid_user=bool(m["inv"]),
                        method=_method(m["method"])) for _ in range(int(m["n"]))]
        elif m := _FAILED.match(msg):
            evs = [dict(ts=ts, user=m["user"], result="fail", invalid_user=bool(m["inv"]),
                        method=_method(m["method"]))]
        else:
            evs = []
            if b := _BREAKIN.search(msg):
                res.breakin_ips.add(b["ip"])
                pid_ip.setdefault(pid, b["ip"])
            elif _TOO_MANY.match(msg) and pid in pid_ip:
                res.too_many_ips.add(pid_ip[pid])
            continue

        ip = m["ip"]
        pid_ip[pid] = ip
        res.events.setdefault(ip, []).extend(evs)
        res.parsed += 1
    return res


def windows(events: list[dict], window_s: int = 600) -> Iterator[list[dict]]:
    """한 IP의 이벤트를 10분 단위 윈도우로 자른다 (첫 이벤트 기준 tumbling window)."""
    evs = sorted(events, key=lambda e: e["ts"])
    cur: list[dict] = []
    for e in evs:
        if cur and e["ts"] - cur[0]["ts"] >= window_s:
            yield cur
            cur = []
        cur.append(e)
    if cur:
        yield cur
