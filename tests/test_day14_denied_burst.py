"""R11: 범위 밖 고객 조회 거부 반복(ID 순차 조회 탐색) 검증."""
from datetime import datetime, timedelta, timezone

from app.detection import Detector

KST = timezone(timedelta(hours=9))
T0 = datetime(2026, 11, 10, 14, 0, tzinfo=KST)


def denied(t, user="agent01", detail="not assigned"):
    return {"ts": t.astimezone(timezone.utc).isoformat(), "username": user, "action": "customer.view",
            "result": "denied", "rows": 0, "detail": detail, "ip": "10.0.0.5", "resource": "customer/9"}


def test_fires_on_tenth_denied_in_ten_minutes():
    alerts = Detector().run([denied(T0 + timedelta(seconds=20 * i)) for i in range(10)])
    assert [a.rule_id for a in alerts] == ["R11"]
    assert alerts[0].response == "stepup" and alerts[0].detail["denied_in_window"] == 10


def test_nine_denials_or_slow_pace_does_not_fire():
    assert Detector().run([denied(T0 + timedelta(seconds=20 * i)) for i in range(9)]) == []
    assert Detector().run([denied(T0 + timedelta(minutes=2 * i)) for i in range(12)]) == []  # 10분 창에 5건


def test_other_denials_are_not_counted():
    ev = [denied(T0 + timedelta(seconds=10 * i), detail="role not allowed") for i in range(20)]
    assert Detector().run(ev) == []


def test_counts_per_user():
    ev = [denied(T0 + timedelta(seconds=10 * i), user=f"agent0{i % 2 + 1}") for i in range(18)]  # 각 9건
    assert Detector().run(ev) == []


def test_server_integration_sweep_requires_stepup(tmp_path, monkeypatch):
    import importlib
    from fastapi.testclient import TestClient
    monkeypatch.setenv("DEFENSE_DB", str(tmp_path / "t.db"))
    monkeypatch.setenv("DEFENSE_AUDIT_LOG", str(tmp_path / "a.jsonl"))
    monkeypatch.setenv("DEFENSE_MODE", "on")
    from app import config
    importlib.reload(config)
    from app import audit, response
    audit._last_hash.clear()
    response.reset()
    from scripts import seed
    importlib.reload(seed)
    seed.main(n_customers=1000)
    from app import main
    with TestClient(main.app) as c:
        r = c.post("/auth/login", json={"username": "agent01", "password": "Demo#2026pw"})
        h = {"Authorization": f"Bearer {r.json()['access_token']}"}
        codes = [c.get(f"/customers/{i}", headers=h).status_code for i in range(1, 60)]
    assert 428 in codes  # 범위 밖 조회가 계속 거부되다 재인증 요구로 막힘
