"""허니토큰(미끼 고객) 검증: 정상 업무와 겹치지 않는 위치에 심고, 닿으면 즉시 대응한다."""
import importlib
import sqlite3

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


def q(sql, args=()):
    from app import db as dbm
    conn = dbm.connect()
    r = [dict(x) for x in conn.execute(sql, args)]
    conn.close()
    return r


def decoy_ids():
    return [r["id"] for r in q("SELECT id FROM customers WHERE decoy=1 ORDER BY id")]


def status(user):
    return q("SELECT status FROM users WHERE username=?", (user,))[0]["status"]


def test_decoys_are_placed_deep_and_unassigned(client):
    ids = decoy_ids()
    assert ids and min(ids) > 4000 * 0.4  # 앞쪽 40%에는 없음
    assert all(r["assigned_agent_id"] is None for r in q("SELECT assigned_agent_id FROM customers WHERE decoy=1"))


def test_agents_never_see_decoys_in_their_lists(client):
    h = tok(client, "agent01")
    seen = []
    for p in range(1, 30):
        r = client.get(f"/customers?page={p}&size=50", headers=h)
        if r.status_code != 200 or not r.json()["items"]:
            break
        seen += [i["id"] for i in r.json()["items"]]
        if status("agent01") != "active":
            break
    assert not set(seen) & set(decoy_ids())
    assert q("SELECT COUNT(*) n FROM audit_logs WHERE action='honeytoken.access'")[0]["n"] == 0


def test_agent_probing_a_decoy_id_is_denied_alerted_and_locked(client):
    h = tok(client, "agent01")
    d = decoy_ids()[0]
    r = client.get(f"/customers/{d}", headers=h)
    assert r.status_code == 403
    assert q("SELECT COUNT(*) n FROM audit_logs WHERE action='honeytoken.access' AND username='agent01'")[0]["n"] == 1
    assert "R10" in [a["rule_id"] for a in q("SELECT rule_id FROM alerts WHERE username='agent01'")]
    assert status("agent01") == "locked"
    assert client.get("/customers?page=1&size=10", headers=h).status_code in (401, 403)


def test_admin_deep_page_jump_hits_decoy_and_is_locked(client):
    h = tok(client, "admin01")
    r = client.get("/customers?page=40&size=50", headers=h)  # id 1951~2000 구간 (미끼 2000 포함)
    assert r.status_code == 200
    assert "R10" in [a["rule_id"] for a in q("SELECT rule_id FROM alerts WHERE username='admin01'")]
    assert status("admin01") == "locked"


def test_normal_work_does_not_touch_decoys(client):
    h = tok(client, "admin01")
    assert client.get("/customers/5", headers=h).status_code == 200
    assert client.get("/customers?page=1&size=50", headers=h).status_code == 200
    assert client.get("/customers/export?limit=100&reason=정기 점검 보고", headers=h).status_code == 200
    ag = tok(client, "agent02")
    assert client.get("/customers?page=1&size=20", headers=ag).status_code == 200
    assert q("SELECT COUNT(*) n FROM audit_logs WHERE action='honeytoken.access'")[0]["n"] == 0
    assert "R10" not in [a["rule_id"] for a in q("SELECT rule_id FROM alerts")]


def test_no_lock_when_defense_off(client, monkeypatch):
    monkeypatch.setenv("DEFENSE_MODE", "off")
    h = tok(client, "admin01")
    assert client.get("/customers?page=40&size=50", headers=h).status_code == 200
    assert status("admin01") == "active"


def test_existing_database_is_migrated(tmp_path, monkeypatch):
    path = tmp_path / "old.db"
    conn = sqlite3.connect(path)
    conn.execute("CREATE TABLE customers(id INTEGER PRIMARY KEY, name TEXT, phone TEXT, email TEXT, rrn TEXT, address TEXT, assigned_agent_id INTEGER)")
    conn.commit()
    conn.close()
    monkeypatch.setenv("DEFENSE_DB", str(path))
    from app import config
    importlib.reload(config)
    from app import db as dbm
    importlib.reload(dbm)
    dbm.init_db()
    cols = [r[1] for r in sqlite3.connect(path).execute("PRAGMA table_info(customers)")]
    assert "decoy" in cols
