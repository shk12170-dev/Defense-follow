"""2차 보완 검증: 누적 조회량(저속 공격), 단계적 대응, 반출 사전 차단."""
import importlib
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from app.detection import Detector

PW = "Demo#2026pw"
KST = timezone(timedelta(hours=9))


def ev(ts, user="insider01", action="customer.list", rows=50, result="ok", detail=None):
    return {"ts": ts.astimezone(timezone.utc).isoformat(), "username": user, "action": action,
            "result": result, "rows": rows, "detail": detail, "ip": "10.0.0.9", "resource": None}


def slow_attack(rate_per_min, hours=8):
    start = datetime(2026, 11, 10, 14, 0, tzinfo=KST)
    step = 50 / rate_per_min
    events, t = [], start
    while t < start + timedelta(hours=hours):
        events.append(ev(t))
        t += timedelta(minutes=step)
    return events


# ---------- 누적 조회량 + 단계적 대응 (엔진) ----------
def test_slow_attack_missed_by_r1_but_caught_by_daily_rules():
    alerts = Detector().run(slow_attack(10))  # 분당 10건: R1(10분 300건)은 못 잡는 속도
    ids = [a.rule_id for a in alerts]
    assert "R1" not in ids
    assert ids == ["R5", "R6"]  # 먼저 경고, 이후 차단 단계
    warn, block = alerts
    assert warn.severity == "medium" and block.severity == "high"
    assert warn.detail["rows_in_window"] >= 1200 and block.detail["rows_in_window"] >= 2000


def test_very_slow_attack_only_warned():
    alerts = Detector().run(slow_attack(3))  # 분당 3건: 8시간 1,440건
    assert [a.rule_id for a in alerts] == ["R5"]


def test_normal_day_has_no_daily_alerts():
    start = datetime(2026, 11, 10, 9, 0, tzinfo=KST)
    events = [ev(start + timedelta(minutes=5 * i), rows=5, action="customer.search") for i in range(96)]  # 480건/8시간
    assert Detector().run(events) == []


def test_daily_window_rolls_over():
    """24시간이 지난 조회는 누적에서 빠진다."""
    d = Detector()
    day1 = datetime(2026, 11, 10, 10, 0, tzinfo=KST)
    # 11분 간격이라 R1(10분 300건)에는 걸리지 않는 속도로 하루 750건
    assert d.run([ev(day1 + timedelta(minutes=11 * i), rows=50) for i in range(15)]) == []
    # 26시간 뒤 같은 양: 전날 조회는 24시간 창에서 빠졌으므로 합산되지 않는다 (합산됐다면 1,500건으로 R5 발동)
    assert d.run([ev(day1 + timedelta(hours=26, minutes=11 * i), rows=50) for i in range(15)]) == []


def test_r7_does_not_lock_but_r6_does():
    d = Detector()
    r7 = d.run([ev(datetime(2026, 11, 10, 15, 0, tzinfo=KST), user="admin01", action="customer.export", rows=0,
                   result="blocked", detail="pre-block: 250건")])
    assert [a.rule_id for a in r7] == ["R7"] and r7[0].lock is False
    r6 = Detector().run(slow_attack(10))[-1]
    assert r6.lock is None  # 심각도(high)로 판단 -> 잠금


# ---------- 서버 통합 ----------
@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("DEFENSE_DB", str(tmp_path / "t.db"))
    monkeypatch.setenv("DEFENSE_AUDIT_LOG", str(tmp_path / "audit.jsonl"))
    monkeypatch.setenv("DEFENSE_MODE", "on")
    from app import config
    importlib.reload(config)
    from app import audit, response
    audit._last_hash.clear()
    response.reset()
    from scripts import seed
    importlib.reload(seed)
    seed.main(n_customers=4000)
    from app import main
    with TestClient(main.app) as c:
        yield c


def tok(c, user):
    r = c.post("/auth/login", json={"username": user, "password": PW})
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


def status_of(user):
    from app import db as dbm
    conn = dbm.connect()
    s = conn.execute("SELECT status FROM users WHERE username=?", (user,)).fetchone()["status"]
    conn.close()
    return s


def test_export_blocked_only_after_bulk_read(client):
    a = tok(client, "admin01")
    # 조회량이 적으면 내보내기 허용
    for p in range(1, 3):  # 100건 (기준 200건 미만)
        client.get(f"/customers?page={p}&size=50", headers=a)
    assert client.get("/customers/export?limit=10&reason=정기 점검 보고", headers=a).status_code == 200
    # 기준 이상으로 더 읽으면 차단
    for p in range(3, 6):
        client.get(f"/customers?page={p}&size=50", headers=a)
    r = client.get("/customers/export?limit=10&reason=정기 점검 보고", headers=a)
    assert r.status_code == 403 and "차단" in r.json()["detail"]


def test_blocked_export_returns_no_data_and_repeat_attempts_stay_blocked(client):
    a = tok(client, "admin01")
    for p in range(1, 6):
        client.get(f"/customers?page={p}&size=50", headers=a)
    for _ in range(3):
        r = client.get("/customers/export?limit=1000&reason=반복 시도 시험", headers=a)
        assert r.status_code == 403 and "items" not in r.json()
    s = client.get("/stats", headers=tok(client, "admin02")).json()
    assert any(e["result"] == "blocked" for e in s["recent_events"])  # 대시보드에 보임


def test_export_is_not_blocked_when_defense_off(client, monkeypatch):
    monkeypatch.setenv("DEFENSE_MODE", "off")
    a = tok(client, "admin01")
    for p in range(1, 6):
        client.get(f"/customers?page={p}&size=50", headers=a)
    assert client.get("/customers/export?limit=10&reason=방어 끔 시험", headers=a).status_code == 200


def test_other_users_reads_do_not_block_my_export(client):
    """조회량은 사용자별로 계산한다."""
    ag = tok(client, "agent01")
    for p in range(1, 6):
        client.get(f"/customers?page={p}&size=50", headers=ag)
    assert client.get("/customers/export?limit=10&reason=타인 조회와 무관", headers=tok(client, "admin01")).status_code == 200


def test_warn_stage_does_not_lock_account(client):
    """경고 단계 경보는 계정을 잠그지 않고 response.warn 이벤트만 남긴다."""
    from app import db as dbm
    from app import response
    conn = dbm.connect()
    user = conn.execute("SELECT * FROM users WHERE username='agent02'").fetchone()
    from app.audit import write_audit
    # 하루 누적 1,000건을 낮은 속도로 직접 기록 (조회 API의 50건 상한 때문에 여러 번 나눠 기록)
    now = datetime.now(timezone.utc)
    base = now - timedelta(hours=6)
    for i in range(25):  # 25 x 50 = 1,250건 (경고 기준 1,200건 초과)
        ts = base + timedelta(minutes=14 * i)
        conn.execute("INSERT INTO audit_logs(ts,user_id,username,role,action,resource,detail,ip,result,rows) VALUES(?,?,?,?,?,?,?,?,?,?)",
                     (ts.isoformat(timespec="milliseconds"), user["id"], "agent02", "agent", "customer.list", "x", None, "1.1.1.1", "ok", 50))
    conn.commit()
    conn.close()
    # 서버 탐지기는 실시간 이벤트로만 판단하므로, 같은 이벤트를 훅에 직접 전달한다
    conn = dbm.connect()
    for i in range(25):
        ts = base + timedelta(minutes=14 * i)
        response._on_event(conn, {"ts": ts.isoformat(), "user_id": user["id"], "username": "agent02", "role": "agent",
                                  "action": "customer.list", "resource": "x", "detail": None, "ip": "1.1.1.1",
                                  "result": "ok", "rows": 50})
    conn.close()
    assert status_of("agent02") == "active"
    a = tok(client, "admin02")
    assert any(x["rule_id"] == "R5" for x in client.get("/alerts", headers=a).json()["items"])
    assert client.get("/audit?action=response.warn", headers=a).json()["count"] >= 1
