"""R8 사용자별 기준선(UEBA) 검증."""
from datetime import datetime, timedelta, timezone

from app.detection import Detector

KST = timezone(timedelta(hours=9))


def ev(ts, rows, user="light01", action="customer.search"):
    return {"ts": ts.astimezone(timezone.utc).isoformat(), "username": user, "action": action,
            "result": "ok", "rows": rows, "detail": None, "ip": "10.0.0.5", "resource": None}


def light_days(n, start, per_day=100, user="light01"):
    """하루 약 per_day건(10건씩)을 조회하는 업무량이 적은 사용자의 n일."""
    out = []
    for d in range(n):
        t = start + timedelta(days=d, hours=9)
        for i in range(per_day // 10):
            out.append(ev(t + timedelta(minutes=20 * i), 10, user))
    return out


def attack_day(day, total, user="light01"):
    t = day + timedelta(hours=10)
    return [ev(t + timedelta(minutes=15 * i), 50, user, "customer.list") for i in range(total // 50)]


START = datetime(2026, 10, 1, tzinfo=KST)


def test_light_user_spike_below_fixed_thresholds_is_warned():
    events = light_days(7, START) + attack_day(START + timedelta(days=7), 700)
    alerts = Detector().run(events)
    assert [a.rule_id for a in alerts] == ["R8"]  # 700건: R1(300/10분)·R5(1,200)에는 못 미침
    a = alerts[0]
    assert a.lock is False and a.severity == "medium"
    assert a.detail["rows_today"] >= 500 and a.detail["baseline_days"] == 7


def test_no_alert_without_enough_baseline_days():
    events = light_days(2, START) + attack_day(START + timedelta(days=2), 700)
    assert Detector().run(events) == []  # 기준선 2일 < min_days 3


def test_normal_variation_not_flagged():
    events = light_days(7, START) + light_days(1, START + timedelta(days=7), per_day=250)
    assert Detector().run(events) == []  # 평소의 2.5배: 4배 미만, 최소 500건 미만


def test_heavy_user_not_flagged_by_baseline():
    heavy = light_days(7, START, per_day=900, user="heavy01") + light_days(1, START + timedelta(days=7), per_day=1100, user="heavy01")
    assert "R8" not in [a.rule_id for a in Detector().run(heavy)]  # 기준선이 높아 4배가 R5·R6보다 큼


def test_baseline_is_per_user():
    events = (light_days(7, START) + light_days(7, START, per_day=900, user="heavy01")
              + attack_day(START + timedelta(days=7), 700))
    alerts = Detector().run(sorted(events, key=lambda e: e["ts"]))
    # 업무량이 많은 사용자의 다른 경보(테스트 데이터가 시간을 넘김)는 무시하고 R8만 본다
    assert [(a.rule_id, a.username) for a in alerts if a.rule_id == "R8"] == [("R8", "light01")]
