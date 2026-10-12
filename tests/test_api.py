"""API 동작 테스트.

모델 출력에 의존하지 않도록 가짜 모델(StubModel)을 주입한다.
(재학습할 때마다 테스트가 깨지는 문제 방지 — 모델 품질은 tests/test_model.py에서 따로 본다)
"""
import os

os.environ.setdefault("ALLOWLIST", "10.0.0.0/8")

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

import app.main as main  # noqa: E402

client = TestClient(main.app)
T0 = 1790000000.0


class StubModel:
    def __init__(self, p):
        self.p = p
        self.seen = []

    def predict_proba(self, x):
        self.seen.append(x[0])
        return [[1 - self.p, self.p]]


@pytest.fixture(autouse=True)
def fresh_state(monkeypatch):
    monkeypatch.setattr(main, "_blocklist", {})
    monkeypatch.setattr(main, "_history", main.IPHistory())


def ev(i, user, ok, gap=5.0, method="password", invalid=False, t0=T0):
    return {"ts": t0 + i * gap, "user": user, "result": "success" if ok else "fail",
            "invalid_user": invalid, "method": method}


def post(ip, events):
    return client.post("/v1/predict", json={"ip": ip, "events": events})


def test_health_lists_features():
    body = client.get("/health").json()
    assert body["status"] == "ok" and body["features"] == main._feature_names


def test_successful_login_is_allowed_by_rule():
    body = post("203.0.113.10", [ev(0, "min", True, method="publickey")]).json()
    assert body["decision"] == "allow" and body["stage"] == "rule_allow"


def test_brute_force_is_blocked_by_rule():
    body = post("198.51.100.1", [ev(i, "root", False, gap=2) for i in range(40)]).json()
    assert body["decision"] == "block" and body["stage"] == "rule_block"
    assert "198.51.100.1" in [x["ip"] for x in client.get("/v1/blocklist").json()["items"]]


@pytest.mark.parametrize("p,decision", [(0.9, "block"), (0.1, "allow")])
def test_gray_zone_follows_model(monkeypatch, p, decision):
    monkeypatch.setattr(main, "_model", StubModel(p))
    body = post("198.51.100.2", [ev(i, "oracle", False, gap=8, invalid=True) for i in range(5)]).json()
    assert body["stage"] == "model" and body["decision"] == decision
    assert body["continue_probability"] == p


def test_history_accumulates_between_calls(monkeypatch):
    stub = StubModel(0.1)
    monkeypatch.setattr(main, "_model", stub)
    post("198.51.100.3", [ev(i, "root", False) for i in range(3)])
    body = post("198.51.100.3", [ev(i, "root", False, t0=T0 + 1200) for i in range(3)]).json()
    assert body["features"]["hist_windows_24h"] == 1.0
    assert body["features"]["hist_log_fails"] > 0


def test_events_outside_10min_window_are_dropped(monkeypatch):
    monkeypatch.setattr(main, "_model", StubModel(0.1))
    old = [ev(0, "root", False, t0=T0 - 3600)]
    new = [ev(i, "root", False) for i in range(3)]
    body = post("198.51.100.4", old + new).json()
    assert body["dropped_old_events"] == 1
    assert body["features"]["n_attempts"] == 3.0


def test_allowlisted_ip_is_never_blocked():
    body = post("10.1.2.3", [ev(i, "root", False, gap=1) for i in range(50)]).json()
    assert body["decision"] == "allow" and body["stage"] == "allowlist"


def test_ipv6_is_normalized_for_unblock():
    post("2001:0db8:0:0:0:0:0:1", [ev(i, "admin", False, gap=1) for i in range(30)])
    assert client.delete("/v1/blocklist/2001:db8::1").status_code == 200
    assert client.delete("/v1/blocklist/2001:db8::1").status_code == 404


def test_invalid_input_rejected():
    assert post("not-an-ip", [ev(0, "a", True)]).status_code == 422
    assert post("1.2.3.4", []).status_code == 422
