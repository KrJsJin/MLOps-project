import pytest

from loginguard.features import FEATURE_NAMES, extract_features, triage


def test_feature_keys_match_feature_names():
    f = extract_features([{"ts": 0, "user": "min", "result": "success"}])
    assert list(f) == FEATURE_NAMES


def test_success_after_fails_detected():
    evs = [{"ts": i, "user": "kim", "result": "fail"} for i in range(4)]
    evs.append({"ts": 10, "user": "kim", "result": "success"})
    assert extract_features(evs)["success_after_fails"] == 1.0


def test_iso_timestamps_and_unsorted_input():
    evs = [{"ts": "2026-10-12T07:00:10Z", "user": "a", "result": "fail"},
           {"ts": "2026-10-12T07:00:00Z", "user": "a", "result": "fail"}]
    assert extract_features(evs)["mean_interval_s"] == pytest.approx(10.0)


def test_triage_zones():
    ok = extract_features([{"ts": 0, "user": "a", "result": "success"}])
    many = extract_features([{"ts": i, "user": "root", "result": "fail"} for i in range(25)])
    few = extract_features([{"ts": i, "user": "root", "result": "fail"} for i in range(3)])
    assert (triage(ok), triage(many), triage(few)) == ("model", "rule_block", "model")


def test_empty_events_raise():
    with pytest.raises(ValueError):
        extract_features([])


def test_success_alert_requires_attack_history():
    from loginguard.features import IPHistory, success_alert
    typo_user = extract_features([{"ts": i, "user": "min", "result": "fail"} for i in range(4)]
                                 + [{"ts": 10, "user": "min", "result": "success"}])
    typo_user.update(IPHistory().features("a", 0))
    assert not success_alert(typo_user)            # 오타 친 정상 사용자 → 경보 없음

    h = IPHistory()
    h.add("b", 0, 500, 50)
    attacker = extract_features([{"ts": 1000, "user": "root", "result": "success"}])
    attacker.update(h.features("b", 1000))
    assert success_alert(attacker)                 # 50회 실패하던 IP의 성공 → 경보
