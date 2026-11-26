import pytest

from scripts import benchmark as b


@pytest.fixture()
def env_guard(monkeypatch):
    # benchmark가 os.environ을 직접 바꾸므로, 테스트 종료 시 원복되도록 먼저 등록해 둔다
    for k in ("DEFENSE_DB", "DEFENSE_AUDIT_LOG", "DEFENSE_ALERT_LOG", "DEFENSE_MODE"):
        monkeypatch.setenv(k, "x")


def test_scenarios_defense_on_reduces_damage(env_guard):
    off = b.run_scenarios("off", 4000)
    on = b.run_scenarios("on", 4000)
    # 방어 OFF: 차단·경보 없음
    assert off["bulk"]["blocked"] is False and off["bulk"]["alerts"] == 0
    assert off["exfil"]["exports_done"] == 5 and off["exfil"]["final_status"] == "active"
    # 방어 ON: 조회는 300건 선에서 차단
    assert on["bulk"]["blocked"] is True and on["bulk"]["rows"] == 300 and on["bulk"]["block_request"] == 7
    # 방어 ON: 내보내기는 실행되기 전에 거부된다 (2차 보완). 계정은 잠그지 않고 경보만 남긴다
    assert on["exfil"]["exports_done"] == 0 and on["exfil"]["blocked"] is True
    assert on["exfil"]["rows"] == 250 and on["exfil"]["final_status"] == "active"
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
    assert a["alerts"] == a["locks"] + a["warns"]
    low, high = b.run_false_positive(threshold=200), b.run_false_positive(threshold=500)
    assert low["locks"] >= a["locks"] >= high["locks"]


def test_daily_warning_is_rare_enough_for_normal_work():
    """R5 경고가 정상 업무에서 너무 잦으면(알림 피로) 안 된다. 상담원·일의 10% 미만이어야 한다."""
    fp = b.run_false_positive()
    assert fp["by_rule"]["R5"] / fp["agent_days"] < 0.10
    assert fp["by_rule"]["R6"] == 0  # 하루 2,000건 차단 기준은 정상 업무에서 발동하지 않는다


def test_evasion_slow_attacker_now_caught_by_daily_rules():
    res = {e["rate"]: e for e in b.run_evasion()}
    # 분당 10·20건: R1(10분 300건)은 못 잡지만 일일 누적 규칙이 경고 후 차단한다
    for rate in (10, 20):
        assert res[rate]["warn_rule"] == "R5" and res[rate]["lock_rule"] == "R6"
        assert res[rate]["warn_rows"] < res[rate]["lock_rows"] == res[rate]["rows_leaked"] == 2000
    # 빠른 공격은 기존대로 R1이 차단
    assert res[60]["lock_rule"] == "R1" and res[150]["lock_rule"] == "R1"
    assert res[150]["lock_min"] < res[60]["lock_min"]
    # 한계: 하루 누적 기준(2,000건) 미만으로 천천히 빼가면 경고만 나고 차단하지 못한다
    assert res[3]["lock_rule"] is None and res[3]["detected"] is False
    assert res[3]["rows_leaked"] == res[3]["total_rows"]


def test_report_rendering_escapes_and_contains_sections():
    scen = {"bulk": {"rows": 1, "blocked": False, "block_request": None, "block_ms": None,
                     "alert_delay_ms": None, "alerts": 0},
            "dormant": {"login_denied": True, "alert_delay_ms": None, "alerts": 0},
            "exfil": {"rows": 1, "exports_done": 1, "blocked": False, "final_status": "active",
                      "alert_delay_ms": None, "alerts": 0}}
    evasion = [{"rate": r, "total_rows": 100, "warn_rule": "R5", "warn_min": 1.0, "warn_rows": 50,
                "lock_rule": None, "lock_min": None, "lock_rows": None, "rows_leaked": 100, "quota_leaked": 100, "detected": False}
               for r in (10, 20)]
    res = {
        "generated": "t<script>", "customers": 10,
        "scenarios": {"off": scen, "on": scen},
        "overhead": {m: {"requests": 1, "mean_ms": 1.0, "p95_ms": 2.0} for m in ("off", "on")},
        "false_positive": {"days": 1, "events": 1, "agent_days": 5, "alerts": 0, "locks": 0, "warns": 0,
                           "by_rule": {"R1": 0}, "examples": []},
        "evasion": evasion,
        "tradeoff": [{"threshold": 300, "fp_locks": 0, "agent_days": 5, "leak_at_60": 300, "detected": True}],
    }
    html_out, md = b.to_html(res), b.to_markdown(res)
    assert "<script>" not in html_out and "&lt;script&gt;" in html_out
    for title in ("시나리오 1", "성능 오버헤드", "2차 보완 전후", "오탐 평가", "저속 공격 분석", "임계값 조정"):
        assert title in md and title in html_out
