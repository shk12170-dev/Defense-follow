import importlib

import pytest
from fastapi.testclient import TestClient

PW = "Demo#2026pw"


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("DEFENSE_DB", str(tmp_path / "t.db"))
    monkeypatch.setenv("DEFENSE_AUDIT_LOG", str(tmp_path / "audit.jsonl"))
    from app import config
    importlib.reload(config)
    from scripts import seed
    importlib.reload(seed)
    seed.main(n_customers=200)
    from app import main
    with TestClient(main.app) as c:
        yield c


def login(c, user, pw=PW):
    return c.post("/auth/login", json={"username": user, "password": pw})


def auth(c, user):
    return {"Authorization": f"Bearer {login(c, user).json()['access_token']}"}


def test_login_ok_and_fail(client):
    assert login(client, "agent01").status_code == 200
    assert login(client, "agent01", "wrong").status_code == 401
    assert login(client, "nobody").status_code == 401


def test_dormant_and_retired_cannot_login(client):
    assert login(client, "retired01").status_code == 403
    assert login(client, "dormant01").status_code == 403


def test_no_token_rejected(client):
    assert client.get("/customers").status_code == 401
    assert client.get("/customers", headers={"Authorization": "Bearer junk"}).status_code == 401


def test_dba_denied(client):
    assert client.get("/customers", headers=auth(client, "dba01")).status_code == 403


def test_agent_sees_only_own_customers_masked(client):
    h = auth(client, "agent01")
    items = client.get("/customers?size=50", headers=h).json()["items"]
    assert items
    for it in items:
        assert "*" in it["name"] or len(it["name"]) == 1
        assert it["phone"].count("****") == 1
        assert it["rrn"].endswith("******")
    # 다른 상담원 담당 고객 접근 차단
    from app import db as dbm
    conn = dbm.connect()
    other = conn.execute(
        "SELECT c.id FROM customers c JOIN users u ON u.id=c.assigned_agent_id WHERE u.username!='agent01' LIMIT 1"
    ).fetchone()["id"]
    conn.close()
    assert client.get(f"/customers/{other}", headers=h).status_code == 403


def test_page_size_capped(client):
    h = auth(client, "admin01")
    assert len(client.get("/customers?size=9999", headers=h).json()["items"]) <= 50


def test_unmask_rules(client):
    a, ag = auth(client, "admin01"), auth(client, "agent01")
    assert client.get("/customers/1?unmask=true", headers=ag).status_code == 403
    assert client.get("/customers/1?unmask=true", headers=a).status_code == 400  # 사유 없음
    r = client.get("/customers/1?unmask=true&reason=고객 요청 확인", headers=a)
    assert r.status_code == 200 and "*" not in r.json()["phone"]


def test_audit_logged_to_db_and_file(client, tmp_path):
    login(client, "agent01", "wrong")
    login(client, "agent01")
    client.get("/customers", headers=auth(client, "agent01"))
    from app import config, db as dbm
    conn = dbm.connect()
    actions = {(r["action"], r["result"]) for r in conn.execute("SELECT action,result FROM audit_logs")}
    conn.close()
    assert ("auth.login", "failed") in actions
    assert ("auth.login", "ok") in actions
    assert ("customer.list", "ok") in actions
    assert config.AUDIT_LOG_PATH.read_text(encoding="utf-8").count("\n") >= 3


def test_locked_account_token_revoked_immediately(client):
    h = auth(client, "agent02")
    assert client.get("/me", headers=h).status_code == 200
    from app import db as dbm
    conn = dbm.connect()
    conn.execute("UPDATE users SET status='locked' WHERE username='agent02'")
    conn.commit()
    conn.close()
    assert client.get("/me", headers=h).status_code == 403
