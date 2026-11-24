import importlib
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from app.detection import Detector, load_events_from_file, save_alerts

KST = timezone(timedelta(hours=9))
PW = "Demo#2026pw"


def ev(ts, user="agent01", action="customer.list", result="ok", rows=20, detail=None, ip="10.0.0.5"):
    return {"ts": ts.astimezone(timezone.utc).isoformat(), "username": user, "action": action,
            "result": result, "rows": rows, "detail": detail, "ip": ip, "resource": None}


def kst(h, m=0, day=10):
    return datetime(2026, 11, day, h, m, tzinfo=KST)


def ids(alerts):
    return [a.rule_id for a in alerts]


def test_normal_workday_no_alerts():
    d = Detector()
    events = [ev(kst(9) + timedelta(minutes=7 * i), rows=15) for i in range(20)]  # 업무시간, 7분 간격 15건
    assert d.run(events) == []


def test_r1_bulk_access_fires_once_with_cooldown():
    d = Detector()
    events = [ev(kst(14, i), rows=50) for i in range(12)]  # 12분간 600건
    alerts = d.run(events)
    assert ids(alerts) == ["R1"]
    assert alerts[0].detail["rows_in_window"] >= 300


def test_r1_slow_access_below_threshold():
    d = Detector()
    events = [ev(kst(10, 0) + timedelta(minutes=11 * i), rows=50) for i in range(10)]  # 11분 간격
    assert d.run(events) == []


def test_r2_off_hours():
    d = Detector()
    assert ids(d.run([ev(kst(2, 30))])) == ["R2"]
    assert Detector().run([ev(kst(5, 59))])[0].rule_id == "R2"
    assert Detector().run([ev(kst(6, 0))]) == []
    assert Detector().run([ev(kst(14, 0))]) == []


def test_r2_once_per_day_per_user():
    d = Detector()
    events = [ev(kst(2, i)) for i in range(0, 50, 5)]
    assert ids(d.run(events)) == ["R2"]


def test_r2_ignores_failed_and_non_data():
    d = Detector()
    assert d.run([ev(kst(3), result="denied"), ev(kst(3, 5), action="auth.login")]) == []


@pytest.mark.parametrize("detail", ["status=dormant", "status=locked", "inactive account"])
def test_r3_inactive_account(detail):
    action = "auth.token" if detail == "inactive account" else "auth.login"
    alerts = Detector().run([ev(kst(11), user="retired01", action=action, result="denied", detail=detail, rows=0)])
    assert ids(alerts) == ["R3"]


def test_r3_ignores_wrong_password():
    alerts = Detector().run([ev(kst(11), action="auth.login", result="failed", rows=0)])
    assert alerts == []


def test_r4_bulk_then_export():
    d = Detector()
    events = [ev(kst(15, i), user="admin01", rows=50) for i in range(5)]  # 250건 조회
    events.append(ev(kst(15, 10), user="admin01", action="customer.export", rows=100))
    got = ids(d.run(events))
    # 조회 250건은 R1 임계값(300) 미만이지만, 내보내기 100건이 더해지면 R1도 함께 발동한다
    assert sorted(got) == ["R1", "R4"]


def test_r4_not_fired_for_plain_export():
    d = Detector()
    alerts = d.run([ev(kst(15), user="admin01", action="customer.export", rows=100)])
    assert "R4" not in ids(alerts)


def test_users_are_isolated():
    d = Detector()
    events = []
    for i in range(6):  # 두 사용자가 각각 150건 → 합치면 넘지만 개인별로는 미달
        events.append(ev(kst(14, i), user="agent01", rows=25))
        events.append(ev(kst(14, i), user="agent02", rows=25))
    assert d.run(events) == []


def test_unsorted_events_are_sorted():
    d = Detector()
    events = [ev(kst(14, i), rows=50) for i in range(12)]
    events.reverse()
    assert ids(d.run(events)) == ["R1"]


def test_save_alerts_dedup(tmp_path, monkeypatch):
    monkeypatch.setenv("DEFENSE_DB", str(tmp_path / "t.db"))
    from app import config
    importlib.reload(config)
    from app import db as dbm
    importlib.reload(dbm)
    dbm.init_db()
    alerts = Detector().run([ev(kst(2), user="agent01")])
    conn = dbm.connect()
    assert save_alerts(conn, alerts) == 1
    assert save_alerts(conn, alerts) == 0  # 재분석해도 중복 저장 안 됨
    conn.close()


def test_end_to_end_with_real_audit_log(tmp_path, monkeypatch):
    monkeypatch.setenv("DEFENSE_DB", str(tmp_path / "e.db"))
    monkeypatch.setenv("DEFENSE_AUDIT_LOG", str(tmp_path / "audit.jsonl"))
    from app import config
    importlib.reload(config)
    from app import audit
    audit._last_hash.clear()
    from scripts import seed
    importlib.reload(seed)
    seed.main(n_customers=4000)  # 상담원당 약 800명 → 50건씩 8페이지 조회 가능
    from app import main
    with TestClient(main.app) as c:
        def tok(u):
            return {"Authorization": "Bearer " + c.post("/auth/login", json={"username": u, "password": PW}).json()["access_token"]}
        h = tok("agent01")
        for p in range(1, 9):                      # 상담원이 50건씩 8번 연속 조회
            c.get(f"/customers?page={p}&size=50", headers=h)
        c.post("/auth/login", json={"username": "retired01", "password": PW})  # 퇴사자 로그인 시도
    alerts = Detector().run(load_events_from_file(config.AUDIT_LOG_PATH))
    got = {(a.rule_id, a.user_key) for a in alerts}
    assert ("R1", "agent01") in got
    assert ("R3", "retired01") in got
