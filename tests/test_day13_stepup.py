"""단계적 재인증(step-up) 검증: 첫 발동은 재인증 요구, 반복 시 잠금, 정상 사용자는 계속 업무 가능."""
import importlib

import pytest
from fastapi.testclient import TestClient

from app import totp

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


def row(user):
    from app import db as dbm
    conn = dbm.connect()
    r = dict(conn.execute("SELECT * FROM users WHERE username=?", (user,)).fetchone())
    conn.close()
    return r


def trip_r1(client, h, pages=range(1, 8)):
    for p in pages:
        client.get(f"/customers?page={p}&size=50", headers=h)


def verify(client, user, h, code=None, reason="고객 요청 처리 중 대량 조회"):
    code = code or totp.code_for(row(user)["totp_secret"])
    return client.post("/auth/stepup", json={"code": code, "reason": reason}, headers=h)


def test_totp_matches_rfc6238_test_vector():
    secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"  # RFC 6238 부록의 SHA1 키 "12345678901234567890"
    assert totp.code_for(secret, at=59) == "287082"          # 8자리 94287082 의 뒤 6자리
    assert totp.code_for(secret, at=1111111109) == "081804"  # 8자리 07081804
    assert totp.verify(secret, "287082", at=59) and not totp.verify(secret, "000000", at=59)
    assert totp.verify(secret, "287082", at=59 + 30)         # 앞뒤 1구간 허용
    assert not totp.verify(secret, "287082", at=59 + 120)


def test_first_r1_requires_stepup_not_lock(client):
    h = tok(client, "agent01")
    trip_r1(client, h)
    u = row("agent01")
    assert u["status"] == "active" and u["stepup_required"] == 1
    assert client.get("/customers?page=9&size=50", headers=h).status_code == 428


def test_wrong_code_rejected_and_three_failures_lock(client):
    h = tok(client, "agent01")
    trip_r1(client, h)
    assert verify(client, "agent01", h, code="000000").status_code == 401
    assert row("agent01")["stepup_required"] == 1
    assert verify(client, "agent01", h, code="000001").status_code == 401
    assert verify(client, "agent01", h, code="000002").status_code == 403  # 3회째 실패 → 잠금
    assert row("agent01")["status"] == "locked"


def test_stepup_needs_reason_and_login(client):
    h = tok(client, "agent01")
    trip_r1(client, h)
    assert verify(client, "agent01", h, reason="짧음").status_code == 400
    assert client.post("/auth/stepup", json={"code": "123456", "reason": "사유 사유 사유"}).status_code == 401


def test_correct_code_restores_access_and_logs_reason(client):
    h = tok(client, "agent01")
    trip_r1(client, h)
    assert verify(client, "agent01", h).json() == {"status": "verified"}
    assert row("agent01")["stepup_required"] == 0
    assert client.get("/customers?page=1&size=10", headers=h).status_code == 200  # 같은 토큰으로 계속 가능
    audit = client.get("/audit?action=auth.stepup", headers=tok(client, "admin02")).json()["items"]
    assert audit and "reason=고객 요청 처리 중 대량 조회" in audit[0]["detail"]


def test_legit_user_is_not_locked_right_after_stepup(client):
    """오탐으로 재인증을 거친 정상 사용자는 곧바로 다시 걸리지 않는다 (R1 집계 창이 초기화됨)."""
    h = tok(client, "agent01")
    trip_r1(client, h)
    assert verify(client, "agent01", h).status_code == 200
    for p in range(8, 12):  # 이어서 200건 더 조회
        assert client.get(f"/customers?page={p}&size=50", headers=h).status_code == 200
    assert row("agent01")["status"] == "active"


def test_repeating_the_bulk_read_after_stepup_locks_the_account(client):
    h = tok(client, "agent01")
    trip_r1(client, h)
    assert verify(client, "agent01", h).status_code == 200
    for p in range(8, 20):  # 재인증 후 다시 300건 이상
        client.get(f"/customers?page={p}&size=50", headers=h)
    assert row("agent01")["status"] == "locked"
    a = tok(client, "admin02")
    assert client.get("/audit?action=response.lock", headers=a).json()["count"] >= 1


def test_unlock_clears_pending_stepup(client):
    h = tok(client, "agent01")
    trip_r1(client, h)
    assert verify(client, "agent01", h).status_code == 200
    for p in range(8, 20):
        client.get(f"/customers?page={p}&size=50", headers=h)
    assert client.post("/admin/users/agent01/unlock", headers=tok(client, "admin02")).status_code == 200
    assert row("agent01")["stepup_required"] == 0


def test_stepup_not_required_returns_not_required(client):
    h = tok(client, "agent02")
    assert verify(client, "agent02", h).json() == {"status": "not_required"}


def test_no_stepup_when_defense_off(client, monkeypatch):
    monkeypatch.setenv("DEFENSE_MODE", "off")
    h = tok(client, "agent01")
    trip_r1(client, h, range(1, 10))
    assert row("agent01")["stepup_required"] == 0


def test_secrets_are_per_user_and_existing_db_is_migrated(tmp_path, monkeypatch):
    import sqlite3
    path = tmp_path / "old.db"
    conn = sqlite3.connect(path)
    conn.execute("CREATE TABLE users(id INTEGER PRIMARY KEY, username TEXT, password_hash TEXT, role TEXT, status TEXT, last_login TEXT)")
    conn.commit()
    conn.close()
    monkeypatch.setenv("DEFENSE_DB", str(path))
    from app import config
    importlib.reload(config)
    from app import db as dbm
    importlib.reload(dbm)
    dbm.init_db()
    cols = [r[1] for r in sqlite3.connect(path).execute("PRAGMA table_info(users)")]
    assert "stepup_required" in cols and "totp_secret" in cols
    assert totp.new_secret("demo-mfa-a") != totp.new_secret("demo-mfa-b")
