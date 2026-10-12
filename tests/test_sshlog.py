from loginguard.sshlog import parse_lines, windows

LINES = """\
Dec 10 06:55:46 LabSZ sshd[24200]: reverse mapping checking getaddrinfo for ns.example.com [173.234.31.186] failed - POSSIBLE BREAK-IN ATTEMPT!
Dec 10 06:55:46 LabSZ sshd[24200]: Invalid user webmaster from 173.234.31.186
Dec 10 06:55:48 LabSZ sshd[24200]: Failed password for invalid user webmaster from 173.234.31.186 port 38926 ssh2
Dec 10 07:02:47 LabSZ sshd[24203]: Failed password for root from 5.36.59.76 port 42393 ssh2
Dec 10 07:02:49 LabSZ sshd[24203]: message repeated 5 times: [ Failed password for root from 5.36.59.76 port 42393 ssh2]
Dec 10 07:02:50 LabSZ sshd[24203]: Disconnecting: Too many authentication failures for root [preauth]
Dec 10 09:32:20 LabSZ sshd[24680]: Accepted password for fztu from 119.137.62.142 port 49116 ssh2
Jan  2 01:00:00 LabSZ sshd[30000]: Failed none for invalid user admin from 9.9.9.9 port 1 ssh2
""".splitlines()


def test_parse_counts_and_flags():
    r = parse_lines(LINES)
    assert len(r.events["173.234.31.186"]) == 1
    assert r.events["173.234.31.186"][0]["invalid_user"] is True
    assert len(r.events["5.36.59.76"]) == 6          # 1 + repeated 5
    assert r.events["119.137.62.142"][0]["result"] == "success"
    assert r.breakin_ips == {"173.234.31.186"}
    assert r.too_many_ips == {"5.36.59.76"}


def test_year_rollover():
    r = parse_lines(LINES, start_year=2015)
    dec = r.events["119.137.62.142"][0]["ts"]
    jan = r.events["9.9.9.9"][0]["ts"]
    assert jan > dec


def test_windows_split_at_10_minutes():
    evs = [{"ts": t, "user": "a", "result": "fail"} for t in (0, 100, 599, 600, 1300)]
    assert [len(w) for w in windows(evs)] == [3, 1, 1]
