import importlib
import json

import pytest
from fastapi.testclient import TestClient

PW = "Demo#2026pw"


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("DEFENSE_DB", str(tmp_path / "t.db"))
    monkeypatch.setenv("DEFENSE_AUDIT_LOG", str(tmp_path / "audit.jsonl"))
    from app import config
    importlib.reload(config)
    from app import audit
    audit._last_hash.clear()
    from scripts import seed
    importlib.reload(seed)
    seed.main(n_customers=300)
    from app import main
    with TestClient(main.app) as c:
        yield c


def auth(c, user):
    r = c.post("/auth/login", json={"username": user, "password": PW})
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


def test_search_min_length_and_scope(client):
    h = auth(client, "agent01")
    assert client.get("/customers/search?q=김", headers=h).status_code == 422
    r = client.get("/customers/search?q=user&size=50", headers=h)
    assert r.status_code == 200
    ids = {i["id"] for i in r.json()["items"]}
    from app import db as dbm
    conn = dbm.connect()
    own = {x["id"] for x in conn.execute(
        "SELECT c.id FROM customers c JOIN users u ON u.id=c.assigned_agent_id WHERE u.username='agent01'")}
    conn.close()
    assert ids and ids <= own


def test_search_wildcard_stripped(client):
    h = auth(client, "admin01")
    assert client.get("/customers/search?q=%25%25", headers=h).status_code == 400
    assert client.get("/customers/search?q=_%25_", headers=h).status_code == 400


def test_export_admin_only_with_reason_and_cap(client):
    assert client.get("/customers/export?reason=월간 점검용", headers=auth(client, "agent01")).status_code == 403
    a = auth(client, "admin01")
    assert client.get("/customers/export", headers=a).status_code == 400
    r = client.get("/customers/export?limit=999999&reason=월간 점검용", headers=a)
    assert r.status_code == 200
    assert r.json()["count"] == 300
    assert "*" in r.json()["items"][0]["phone"]  # 내보내기도 마스킹 유지


def test_rows_recorded_in_audit(client):
    client.get("/customers?size=20", headers=auth(client, "admin01"))
    client.get("/customers/export?limit=77&reason=월간 점검용", headers=auth(client, "admin01"))
    from app import db as dbm
    conn = dbm.connect()
    got = {r["action"]: r["rows"] for r in conn.execute(
        "SELECT action, rows FROM audit_logs WHERE action IN ('customer.list','customer.export')")}
    conn.close()
    assert got == {"customer.list": 20, "customer.export": 77}


def test_audit_endpoint_admin_only_and_filter(client):
    assert client.get("/audit", headers=auth(client, "agent01")).status_code == 403
    r = client.get("/audit?action=auth.login&result=ok", headers=auth(client, "admin01"))
    assert r.status_code == 200 and r.json()["count"] >= 2
    assert all(i["action"] == "auth.login" for i in r.json()["items"])


def test_hash_chain_detects_tampering(client):
    from app import audit, config
    client.get("/customers", headers=auth(client, "agent01"))
    client.get("/customers", headers=auth(client, "agent01"))
    assert audit.verify_chain() == (True, None)
    lines = config.AUDIT_LOG_PATH.read_text(encoding="utf-8").splitlines()
    rec = json.loads(lines[1])  # 2번째 줄 = customer.list 기록
    assert rec["action"] == "customer.list"
    rec["rows"] = 999  # 기록 조작
    lines[1] = json.dumps(rec, ensure_ascii=False)
    config.AUDIT_LOG_PATH.write_text("\n".join(lines) + "\n", encoding="utf-8")
    assert audit.verify_chain() == (False, 2)
    # 줄 삭제도 탐지
    del lines[1]
    config.AUDIT_LOG_PATH.write_text("\n".join(lines) + "\n", encoding="utf-8")
    assert audit.verify_chain()[0] is False


def test_chain_survives_restart(client):
    from app import audit, config
    client.get("/customers", headers=auth(client, "agent01"))
    audit._last_hash.clear()  # 서버 재시작 흉내
    client.get("/customers", headers=auth(client, "agent01"))
    assert audit.verify_chain() == (True, None)
