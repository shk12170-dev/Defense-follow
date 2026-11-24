import pytest

from scripts import benchmark as b


@pytest.fixture()
def env_guard(monkeypatch):
    # benchmark가 os.environ을 직접 바꾸므로, 테스트 종료 시 원복되도록 먼저 등록해 둔다
    for k in ("DEFENSE_DB", "DEFENSE_AUDIT_LOG", "DEFENSE_MODE"):
        monkeypatch.setenv(k, "x")


def test_scenarios_defense_on_reduces_damage(env_guard):
    off = b.run_scenarios("off", 4000)
    on = b.run_scenarios("on", 4000)
    # 방어 OFF: 차단·경보 없음
    assert off["bulk"]["blocked"] is False and off["bulk"]["alerts"] == 0
    assert off["exfil"]["exports_done"] == 5 and off["exfil"]["final_status"] == "active"
    # 방어 ON: 300건 선에서 차단, 내보내기는 1회만 성공하고 계정 잠금
    assert on["bulk"]["blocked"] is True and on["bulk"]["rows"] == 300 and on["bulk"]["block_request"] == 7
    assert on["exfil"]["exports_done"] == 1 and on["exfil"]["final_status"] == "locked"
    assert on["exfil"]["rows"] < off["exfil"]["rows"]
    # 경보 지연은 음수가 될 수 없다 (다른 시나리오 경보와 섞이지 않음)
    for k in ("bulk", "dormant", "exfil"):
        d = on[k]["alert_delay_ms"]
        assert d is not None and d >= 0
    # 접근통제는 방어 OFF에서도 동작
    assert off["dormant"]["login_denied"] and on["dormant"]["login_denied"]
    assert off["dormant"]["alerts"] == 0 and on["dormant"]["alerts"] >= 1


def test_false_positive_is_deterministic_and_threshold_tradeoff():
    a = b.run_false_positive()
    assert a == b.run_false_positive()
    assert a["by_rule"]["R2"] == a["by_rule"]["R3"] == a["by_rule"]["R4"] == 0
    low, high = b.run_false_positive(threshold=200), b.run_false_positive(threshold=500)
    assert low["alerts"] >= a["alerts"] >= high["alerts"]


def test_evasion_slow_attacker_is_missed():
    res = {e["rate"]: e for e in b.run_evasion()}
    assert res[10]["detected"] is False and res[20]["detected"] is False
    assert res[60]["detected"] is True and res[150]["detected"] is True
    assert res[150]["minutes"] < res[60]["minutes"]


def test_report_rendering_escapes_and_contains_sections():
    res = {
        "generated": "t<script>", "customers": 10,
        "scenarios": {m: {"bulk": {"rows": 1, "blocked": False, "block_request": None, "block_ms": None,
                                   "alert_delay_ms": None, "alerts": 0},
                          "dormant": {"login_denied": True, "alert_delay_ms": None, "alerts": 0},
                          "exfil": {"rows": 1, "exports_done": 1, "blocked": False, "final_status": "active",
                                    "alert_delay_ms": None, "alerts": 0}} for m in ("off", "on")},
        "overhead": {m: {"requests": 1, "mean_ms": 1.0, "p95_ms": 2.0} for m in ("off", "on")},
        "false_positive": {"days": 1, "events": 1, "agent_days": 5, "alerts": 0,
                           "by_rule": {"R1": 0, "R2": 0, "R3": 0, "R4": 0}, "examples": []},
        "evasion": [{"rate": 10, "detected": False, "minutes": None, "rows_leaked": 1}],
        "tradeoff": [{"threshold": 300, "fp_alerts": 0, "agent_days": 5, "leak_at_60": 300, "detected": True}],
    }
    html_out, md = b.to_html(res), b.to_markdown(res)
    assert "<script>" not in html_out and "&lt;script&gt;" in html_out
    for title in ("시나리오 1", "성능 오버헤드", "오탐 평가", "회피 분석", "임계값 조정"):
        assert title in md and title in html_out
