import os

os.environ.setdefault("ALLOWLIST", "10.0.0.0/8")

from fastapi.testclient import TestClient  # noqa: E402

from app.main import app  # noqa: E402

client = TestClient(app)
T0 = 1790000000.0


def ev(i, user, ok, gap=5.0, method="password", invalid=False):
    return {"ts": T0 + i * gap, "user": user, "result": "success" if ok else "fail",
            "invalid_user": invalid, "method": method}


def test_health():
    r = client.get("/health")
    assert r.status_code == 200 and r.json()["status"] == "ok"


def test_successful_key_login_is_allowed_by_rule():
    r = client.post("/v1/predict", json={"ip": "203.0.113.10",
                                         "events": [ev(0, "min", True, method="publickey")]})
    body = r.json()
    assert r.status_code == 200
    assert body["decision"] == "allow" and body["stage"] == "rule_allow"


def test_brute_force_is_blocked_by_rule():
    events = [ev(i, "root", False, gap=2) for i in range(40)]
    body = client.post("/v1/predict", json={"ip": "198.51.100.1", "events": events}).json()
    assert body["decision"] == "block" and body["stage"] == "rule_block"
    assert "198.51.100.1" in [x["ip"] for x in client.get("/v1/blocklist").json()["items"]]


def test_gray_zone_dictionary_attack_goes_to_model_and_blocks():
    users = ["oracle", "test", "guest", "pi", "support", "mysql", "ftp", "hadoop"]
    events = [ev(i, u, False, gap=8, invalid=True) for i, u in enumerate(users)]
    body = client.post("/v1/predict", json={"ip": "198.51.100.2", "events": events}).json()
    assert body["stage"] == "model"
    assert body["decision"] == "block" and body["attack_probability"] >= 0.5


def test_gray_zone_typo_then_success_is_allowed():
    events = [ev(0, "jiwoo", False, gap=10), ev(1, "jiwoo", False, gap=10), ev(2, "jiwoo", True, gap=10)]
    body = client.post("/v1/predict", json={"ip": "203.0.113.20", "events": events}).json()
    assert body["stage"] == "model"
    assert body["decision"] == "allow"


def test_allowlisted_ip_is_never_blocked():
    events = [ev(i, "root", False, gap=1) for i in range(50)]
    body = client.post("/v1/predict", json={"ip": "10.1.2.3", "events": events}).json()
    assert body["decision"] == "allow" and body["stage"] == "allowlist"


def test_manual_unblock():
    events = [ev(i, "admin", False, gap=1) for i in range(30)]
    client.post("/v1/predict", json={"ip": "198.51.100.9", "events": events})
    assert client.delete("/v1/blocklist/198.51.100.9").status_code == 200
    assert client.delete("/v1/blocklist/198.51.100.9").status_code == 404


def test_invalid_input_rejected():
    assert client.post("/v1/predict", json={"ip": "not-an-ip", "events": [ev(0, "a", True)]}).status_code == 422
    assert client.post("/v1/predict", json={"ip": "1.2.3.4", "events": []}).status_code == 422
