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


# ---------- 서버 재시작 후 복원 ----------
def _restart_db(tmp_path, monkeypatch, days):
    import sqlite3
    from app import config, db as dbm, response
    monkeypatch.setenv("DEFENSE_MODE", "on")
    monkeypatch.setattr(config, "AUDIT_LOG_PATH", tmp_path / "audit.jsonl")
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.executescript(dbm.SCHEMA)
    conn.execute("INSERT INTO users(username,password_hash,role,status) VALUES('light01','x','agent','active')")
    # 기준 시각: 어제(KST) 10시를 '오늘'로 본다. 날짜 경계·R1(10분 300건)에 걸리지 않도록 고정 시각을 쓴다.
    today = datetime.now(KST).replace(hour=10, minute=0, second=0, microsecond=0) - timedelta(days=1)
    def put(t, rows):
        conn.execute("INSERT INTO audit_logs(ts,user_id,username,role,action,result,rows) VALUES(?,1,'light01','agent','customer.search','ok',?)",
                     (t.astimezone(timezone.utc).isoformat(timespec="milliseconds"), rows))
    for d in range(1, days + 1):  # 지난 며칠 동안 하루 100건
        put(today - timedelta(days=d), 100)
    put(today + timedelta(minutes=0), 300)  # 오늘 앞선 조회
    now = today + timedelta(minutes=30)
    conn.commit()
    response.reset()
    return conn, now.astimezone(timezone.utc)


def _today_event(now, rows):
    return {"ts": now.isoformat(timespec="milliseconds"), "username": "light01", "action": "customer.list",
            "result": "ok", "rows": rows, "detail": None, "ip": "10.0.0.5", "resource": None}


def test_baseline_restored_from_db_after_restart(tmp_path, monkeypatch):
    from app import response
    conn, now = _restart_db(tmp_path, monkeypatch, days=7)
    response._on_event(conn, _today_event(now, 250))  # 재시작 직후 첫 이벤트
    rules = [r["rule_id"] for r in conn.execute("SELECT rule_id FROM alerts")]
    assert rules == ["R8"]
    assert conn.execute("SELECT COUNT(*) FROM audit_logs WHERE action='response.warn'").fetchone()[0] == 1
    assert conn.execute("SELECT status FROM users").fetchone()[0] == "active"  # 경고만, 잠금 없음
    response.reset()


def test_restart_without_history_has_no_baseline(tmp_path, monkeypatch):
    from app import response
    conn, now = _restart_db(tmp_path, monkeypatch, days=0)
    response._on_event(conn, _today_event(now, 250))
    assert conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0] == 0
    response.reset()


def test_unlock_forget_keeps_past_baseline(tmp_path, monkeypatch):
    from app import response
    conn, now = _restart_db(tmp_path, monkeypatch, days=7)
    response._on_event(conn, _today_event(now, 250))
    response.forget("light01")  # 잠금 해제 후 재감시: 오늘 누적만 지우고 과거 기준선은 유지
    days = response._detector.daily["light01"]
    assert len(days) == 7
    response.reset()
