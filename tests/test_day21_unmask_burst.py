"""R15: 마스킹 해제(주민번호 원문 조회)가 짧은 시간에 반복."""
import importlib
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from app.detection import Detector

KST = timezone(timedelta(hours=9))
T0 = datetime(2026, 11, 10, 14, 0, tzinfo=KST)


def unmask(t, user="admin01", action="customer.unmask", result="ok"):
    return {"ts": t.astimezone(timezone.utc).isoformat(), "username": user, "action": action, "result": result,
            "rows": 1, "detail": "reason=점검", "ip": "10.0.0.2", "resource": "customer/1"}


def test_tenth_unmask_in_an_hour_fires():
    alerts = Detector().run([unmask(T0 + timedelta(minutes=i)) for i in range(10)])
    r15 = [a for a in alerts if a.rule_id == "R15"]
    assert len(r15) == 1 and r15[0].response == "stepup" and r15[0].detail["unmask_in_window"] == 10


def test_nine_or_spread_out_does_not_fire():
    assert not [a for a in Detector().run([unmask(T0 + timedelta(minutes=i)) for i in range(9)]) if a.rule_id == "R15"]
    spread = [unmask(T0 + timedelta(minutes=7 * i)) for i in range(10)]  # 63분에 걸쳐 10건: 창(60분)에 10건이 안 모임
    assert not [a for a in Detector().run(spread) if a.rule_id == "R15"]


def test_only_successful_unmask_of_same_user_counts():
    ev = [unmask(T0 + timedelta(minutes=i), result="denied") for i in range(12)]
    ev += [unmask(T0 + timedelta(minutes=i), action="customer.view") for i in range(12)]
    ev += [unmask(T0 + timedelta(minutes=i), user=f"admin0{1 + i % 2}") for i in range(12)]  # 두 계정에 6건씩
    assert not [a for a in Detector().run(ev) if a.rule_id == "R15"]


def test_cooldown_prevents_repeated_alerts():
    alerts = Detector().run([unmask(T0 + timedelta(minutes=i)) for i in range(20)])
    assert len([a for a in alerts if a.rule_id == "R15"]) == 1


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
    seed.main(n_customers=500)
    from app import main
    with TestClient(main.app) as c:
        yield c


def admin_headers(c):
    r = c.post("/auth/login", json={"username": "admin01", "password": "Demo#2026pw"})
    return {"Authorization": "Bearer " + r.json()["access_token"]}


def q(sql, args=()):
    from app import db as dbm
    conn = dbm.connect()
    r = [dict(x) for x in conn.execute(sql, args)]
    conn.close()
    return r


def test_repeated_unmask_requires_stepup_without_locking(client):
    h = admin_headers(client)
    codes = [client.get(f"/customers/{i}?unmask=true&reason=월간 점검용 확인", headers=h).status_code for i in range(1, 13)]
    assert codes[:10] == [200] * 10  # 열 번째 원문 조회까지는 통과한 뒤 경보
    assert 428 in codes[10:]  # 이후는 재인증 전까지 거부
    assert "R15" in [a["rule_id"] for a in q("SELECT rule_id FROM alerts")]
    assert q("SELECT status FROM users WHERE username='admin01'")[0]["status"] == "active"


def test_few_unmasks_are_not_flagged(client):
    h = admin_headers(client)
    for i in range(1, 6):
        assert client.get(f"/customers/{i}?unmask=true&reason=월간 점검용 확인", headers=h).status_code == 200
    assert "R15" not in [a["rule_id"] for a in q("SELECT rule_id FROM alerts")]
