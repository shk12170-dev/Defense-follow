"""R14: 한 계정의 조회가 여러 IP에서 동시에 발생(로그인 토큰 탈취·계정 공유)."""
import importlib
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from app.detection import Detector

KST = timezone(timedelta(hours=9))
T0 = datetime(2026, 11, 10, 14, 0, tzinfo=KST)


def view(t, ip, user="agent02", action="customer.view", rows=1):
    return {"ts": t.astimezone(timezone.utc).isoformat(), "username": user, "action": action, "result": "ok",
            "rows": rows, "detail": None, "ip": ip, "resource": "customer/1"}


def test_second_ip_within_ten_minutes_fires():
    alerts = Detector().run([view(T0, "198.51.100.10"), view(T0 + timedelta(minutes=2), "203.0.113.99")])
    assert [a.rule_id for a in alerts] == ["R14"]
    a = alerts[0]
    assert a.response == "stepup" and a.severity == "high" and a.detail["distinct_ips"] == 2 and a.username == "agent02"


def test_same_ip_or_far_apart_does_not_fire():
    assert Detector().run([view(T0 + timedelta(minutes=i), "198.51.100.10") for i in range(20)]) == []
    assert Detector().run([view(T0, "198.51.100.10"), view(T0 + timedelta(minutes=11), "203.0.113.99")]) == []


def test_counts_per_user_and_ignores_non_data_events():
    assert Detector().run([view(T0, "198.51.100.10", "agent01"), view(T0 + timedelta(minutes=1), "203.0.113.99", "agent02")]) == []
    login = dict(view(T0 + timedelta(minutes=1), "203.0.113.99"), action="auth.login")
    assert Detector().run([view(T0, "198.51.100.10"), login]) == []  # 로그인 이벤트는 조회가 아님
    denied = dict(view(T0 + timedelta(minutes=1), "203.0.113.99"), result="denied")
    assert Detector().run([view(T0, "198.51.100.10"), denied]) == []


def test_cooldown_prevents_repeated_alerts():
    ev = [view(T0, "198.51.100.10")] + [view(T0 + timedelta(minutes=1 + i), "203.0.113.99") for i in range(5)]
    assert [a.rule_id for a in Detector().run(ev)] == ["R14"]


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
    seed.main(n_customers=4000)
    from app import main
    with TestClient(main.app) as c:
        yield c


def token(c):
    r = c.post("/auth/login", json={"username": "agent02", "password": "Demo#2026pw"}, headers={"X-Forwarded-For": "198.51.100.10"})
    return {"Authorization": "Bearer " + r.json()["access_token"]}


def get(c, h, ip, page=1):
    return c.get(f"/customers?page={page}&size=10", headers={**h, "X-Forwarded-For": ip})


def q(sql, args=()):
    from app import db as dbm
    conn = dbm.connect()
    r = [dict(x) for x in conn.execute(sql, args)]
    conn.close()
    return r


def test_stolen_token_used_from_another_ip_is_stopped_by_stepup(client):
    h = token(client)
    assert get(client, h, "198.51.100.10").status_code == 200
    assert get(client, h, "203.0.113.99", 2).status_code == 200  # 두 번째 IP의 첫 요청은 통과한 뒤 경보
    assert "R14" in [a["rule_id"] for a in q("SELECT rule_id FROM alerts")]
    assert get(client, h, "203.0.113.99", 3).status_code == 428  # 이후 요청은 재인증 전까지 거부
    assert q("SELECT status FROM users WHERE username='agent02'")[0]["status"] == "active"  # 계정은 잠그지 않음
    assert get(client, h, "198.51.100.10", 4).status_code == 200  # 토큰을 발급받은 IP의 정상 사용자는 계속 사용 가능
    assert get(client, h, "203.0.113.99", 5).status_code == 428


def test_scope_widens_when_another_rule_requires_full_stepup(client):
    h = token(client)
    get(client, h, "198.51.100.10")
    get(client, h, "203.0.113.99", 2)
    q("SELECT 1")
    from app import db as dbm
    conn = dbm.connect()
    conn.execute("UPDATE users SET stepup_scope=NULL WHERE username='agent02'")  # 다른 규칙의 전체 재인증 상태
    conn.commit()
    conn.close()
    assert get(client, h, "198.51.100.10", 3).status_code == 428


def test_token_without_ip_claim_gets_full_stepup(client):
    from app import security
    h = token(client)
    get(client, h, "198.51.100.10")
    get(client, h, "203.0.113.99", 2)
    user = q("SELECT * FROM users WHERE username='agent02'")[0]
    old = {"Authorization": "Bearer " + security.create_token(user)}  # ip 클레임 없는 토큰
    assert get(client, old, "198.51.100.10", 3).status_code == 428


def test_stepup_clears_scope(client):
    from app import totp
    h = token(client)
    get(client, h, "198.51.100.10")
    get(client, h, "203.0.113.99", 2)
    secret = q("SELECT totp_secret FROM users WHERE username='agent02'")[0]["totp_secret"]
    client.post("/auth/stepup", json={"code": totp.code_for(secret), "reason": "모바일 네트워크로 전환함"}, headers=h)
    row = q("SELECT stepup_required, stepup_scope FROM users WHERE username='agent02'")[0]
    assert row["stepup_required"] == 0 and row["stepup_scope"] is None


def test_legitimate_user_can_continue_after_stepup(client):
    from app import totp
    h = token(client)
    get(client, h, "198.51.100.10")
    get(client, h, "203.0.113.99", 2)
    secret = q("SELECT totp_secret FROM users WHERE username='agent02'")[0]["totp_secret"]
    r = client.post("/auth/stepup", json={"code": totp.code_for(secret), "reason": "모바일 네트워크로 전환함"}, headers=h)
    assert r.status_code == 200
    assert get(client, h, "198.51.100.10", 3).status_code == 200


def test_single_ip_session_never_triggers(client):
    h = token(client)
    for p in range(1, 6):
        assert get(client, h, "198.51.100.10", p).status_code == 200
    assert "R14" not in [a["rule_id"] for a in q("SELECT rule_id FROM alerts")]


def test_off_when_defense_off(client, monkeypatch):
    monkeypatch.setenv("DEFENSE_MODE", "off")
    h = token(client)
    get(client, h, "198.51.100.10")
    assert get(client, h, "203.0.113.99", 2).status_code == 200 and get(client, h, "203.0.113.99", 3).status_code == 200
