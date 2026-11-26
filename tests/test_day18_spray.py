"""R13: 분산 IP 비밀번호 스프레이 탐지와 프록시 IP 처리."""
import importlib
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from app.detection import Detector

KST = timezone(timedelta(hours=9))
T0 = datetime(2026, 11, 10, 14, 0, tzinfo=KST)


def fail(t, ip, user="agent05"):
    return {"ts": t.astimezone(timezone.utc).isoformat(), "username": user, "action": "auth.login",
            "result": "failed", "rows": 0, "detail": f"username={user}", "ip": ip, "resource": None}


def test_eight_distinct_ips_in_ten_minutes_fires():
    ev = [fail(T0 + timedelta(seconds=30 * i), f"203.0.113.{i}") for i in range(8)]
    alerts = Detector().run(ev)
    assert [a.rule_id for a in alerts] == ["R13"]
    a = alerts[0]
    assert a.response == "stepup" and a.severity == "high" and a.detail["distinct_ips"] == 8 and a.username == "agent05"


def test_same_ip_repeated_does_not_count_as_spray():
    ev = [fail(T0 + timedelta(seconds=20 * i), "203.0.113.9") for i in range(30)]
    assert "R13" not in [a.rule_id for a in Detector().run(ev)]


def test_seven_ips_or_slow_pace_does_not_fire():
    assert Detector().run([fail(T0 + timedelta(seconds=30 * i), f"203.0.113.{i}") for i in range(7)]) == []
    assert Detector().run([fail(T0 + timedelta(minutes=2 * i), f"203.0.113.{i}") for i in range(12)]) == []  # 10분 창에 5개


def test_counts_per_account_not_globally():
    ev = [fail(T0 + timedelta(seconds=20 * i), f"203.0.113.{i}", user=f"agent0{i % 2 + 1}") for i in range(14)]  # 계정당 7개
    assert Detector().run(ev) == []


def test_successful_logins_and_unknown_users_are_ignored():
    ok = [dict(fail(T0 + timedelta(seconds=10 * i), f"203.0.113.{i}"), result="ok") for i in range(12)]
    unknown = [dict(fail(T0 + timedelta(seconds=10 * i), f"203.0.113.{i}"), username=None) for i in range(12)]
    assert Detector().run(ok) == [] and Detector().run(unknown) == []


# ---------- 서버 통합 ----------
@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("DEFENSE_DB", str(tmp_path / "t.db"))
    monkeypatch.setenv("DEFENSE_AUDIT_LOG", str(tmp_path / "audit.jsonl"))
    monkeypatch.setenv("DEFENSE_MODE", "on")
    monkeypatch.setenv("DEFENSE_TRUSTED_PROXY", "on")
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
        yield c


def attempt(c, ip, pw="wrong"):
    return c.post("/auth/login", json={"username": "agent05", "password": pw}, headers={"X-Forwarded-For": ip})


def q(sql, args=()):
    from app import db as dbm
    conn = dbm.connect()
    r = [dict(x) for x in conn.execute(sql, args)]
    conn.close()
    return r


def test_spray_evades_throttle_but_forces_stepup_even_with_the_right_password(client):
    codes = [attempt(client, f"203.0.113.{i}").status_code for i in range(1, 13)]
    assert set(codes) == {401}  # (아이디, IP) 단위 스로틀(R12)은 피함
    assert "R13" in [a["rule_id"] for a in q("SELECT rule_id FROM alerts")]
    r = attempt(client, "198.51.100.7", pw="Demo#2026pw")  # 공격자가 비밀번호를 알아냄
    assert r.status_code == 200
    h = {"Authorization": "Bearer " + r.json()["access_token"]}
    assert client.get("/customers?page=1&size=10", headers=h).status_code == 428  # 인증 코드 없이는 데이터 불가
    assert q("SELECT status FROM users WHERE username='agent05'")[0]["status"] == "active"  # 계정 잠금은 아님


def test_trusted_proxy_uses_forwarded_ip_for_throttle(client):
    for _ in range(5):
        attempt(client, "203.0.113.50")
    assert attempt(client, "203.0.113.50", pw="Demo#2026pw").status_code == 429  # 그 IP만 거부
    assert attempt(client, "203.0.113.51", pw="Demo#2026pw").status_code == 200  # 다른 IP는 영향 없음


def test_forwarded_header_ignored_when_proxy_not_trusted(client, monkeypatch):
    monkeypatch.setenv("DEFENSE_TRUSTED_PROXY", "off")
    for i in range(6):
        attempt(client, f"203.0.113.{i}")  # 헤더를 위조해도 실제 접속 주소(testclient) 하나로 센다
    assert attempt(client, "203.0.113.99", pw="Demo#2026pw").status_code == 429
