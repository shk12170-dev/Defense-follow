import importlib

import pytest
from fastapi.testclient import TestClient

PW = "Demo#2026pw"


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


def test_bulk_access_locks_account_and_blocks_next_request(client):
    h = tok(client, "agent01")
    codes = [client.get(f"/customers?page={p}&size=50", headers=h).status_code for p in range(1, 12)]
    assert codes[:6] == [200] * 6          # 300건에 도달하는 6번째 요청까지는 응답
    assert 403 in codes[6:]                # 이후 차단
    assert status_of("agent01") == "locked"
    assert client.get("/me", headers=h).status_code == 403   # 기존 토큰도 즉시 무효


def test_alert_saved_and_lock_audited(client):
    h = tok(client, "agent01")
    for p in range(1, 8):
        client.get(f"/customers?page={p}&size=50", headers=h)
    a = tok(client, "admin02")
    alerts = client.get("/alerts?rule_id=R1", headers=a).json()["items"]
    assert alerts and alerts[0]["username"] == "agent01" and alerts[0]["severity"] == "high"
    locks = client.get("/audit?action=response.lock", headers=a).json()["items"]
    assert locks and "R1" in locks[0]["detail"]


def test_exfiltration_locks_admin(client):
    h = tok(client, "admin01")
    for p in range(1, 6):
        client.get(f"/customers?page={p}&size=50", headers=h)
    assert client.get("/customers/export?limit=100&reason=월간 점검용", headers=h).status_code == 200
    assert status_of("admin01") == "locked"
    a = tok(client, "admin02")
    rules = {x["rule_id"] for x in client.get("/alerts", headers=a).json()["items"]}
    assert "R4" in rules


def test_normal_usage_not_locked(client):
    h = tok(client, "agent01")
    for p in range(1, 4):  # 150건
        assert client.get(f"/customers?page={p}&size=50", headers=h).status_code == 200
    assert status_of("agent01") == "active"


def test_unlock_flow_resets_monitoring(client):
    h = tok(client, "agent01")
    for p in range(1, 8):
        client.get(f"/customers?page={p}&size=50", headers=h)
    assert status_of("agent01") == "locked"
    a = tok(client, "admin02")
    assert client.post("/admin/users/agent01/unlock", headers=a).status_code == 200
    assert client.post("/admin/users/agent01/unlock", headers=a).status_code == 409  # 이미 활성
    h2 = tok(client, "agent01")
    assert client.get("/customers?page=1&size=50", headers=h2).status_code == 200  # 이력 초기화됨


def test_unlock_requires_admin_and_not_for_dormant(client):
    assert client.post("/admin/users/agent01/unlock", headers=tok(client, "agent02")).status_code == 403
    assert client.post("/admin/users/retired01/unlock", headers=tok(client, "admin02")).status_code == 409


def test_defense_off_does_not_block(client, monkeypatch):
    monkeypatch.setenv("DEFENSE_MODE", "off")
    h = tok(client, "agent01")
    codes = [client.get(f"/customers?page={p}&size=50", headers=h).status_code for p in range(1, 12)]
    assert set(codes) == {200}
    assert status_of("agent01") == "active"
