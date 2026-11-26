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


def test_bulk_access_requires_stepup_and_blocks_next_request(client):
    """R1은 1단계로 재인증을 요구한다: 계정은 잠기지 않지만 재인증 전까지 데이터 요청이 거부된다(428)."""
    h = tok(client, "agent01")
    codes = [client.get(f"/customers?page={p}&size=50", headers=h).status_code for p in range(1, 12)]
    assert codes[:6] == [200] * 6          # 300건에 도달하는 6번째 요청까지는 응답
    assert 428 in codes[6:] and 200 not in codes[6:]   # 이후 차단
    assert status_of("agent01") == "active"            # 잠그지 않음
    assert client.get("/me", headers=h).status_code == 200  # 재인증 엔드포인트와 /me는 허용


def lock_via_repeated_bulk(client, user="agent01"):
    """재인증을 통과한 뒤 다시 기준을 넘으면(24시간 안) 잠긴다."""
    import sqlite3
    from app import config, totp
    h = tok(client, user)
    for p in range(1, 8):
        client.get(f"/customers?page={p}&size=50", headers=h)
    secret = sqlite3.connect(config.DB_PATH).execute("SELECT totp_secret FROM users WHERE username=?", (user,)).fetchone()[0]
    assert client.post("/auth/stepup", json={"code": totp.code_for(secret), "reason": "고객 요청 처리 중 대량 조회"}, headers=h).status_code == 200
    for p in range(8, 16):
        client.get(f"/customers?page={p}&size=50", headers=h)
    return h


def test_alert_saved_and_stepup_audited_then_lock_on_repeat(client):
    h = tok(client, "agent01")
    for p in range(1, 8):
        client.get(f"/customers?page={p}&size=50", headers=h)
    a = tok(client, "admin02")
    alerts = client.get("/alerts?rule_id=R1", headers=a).json()["items"]
    assert alerts and alerts[0]["username"] == "agent01" and alerts[0]["severity"] == "high"
    steps = client.get("/audit?action=response.stepup", headers=a).json()["items"]
    assert steps and "R1" in steps[0]["detail"]
    assert client.get("/audit?action=response.lock", headers=a).json()["count"] == 0  # 첫 발동은 잠그지 않음


def test_exfiltration_is_blocked_before_it_happens(client):
    """2차 보완: 대량 조회 직후 내보내기는 실행되지 않고 거부된다 (이전에는 실행 후 계정 잠금)."""
    h = tok(client, "admin01")
    for p in range(1, 6):
        client.get(f"/customers?page={p}&size=50", headers=h)  # 250건 조회
    r = client.get("/customers/export?limit=100&reason=월간 점검용", headers=h)
    assert r.status_code == 403
    assert status_of("admin01") == "active"  # 차단만 하고 계정은 잠그지 않는다 (R7은 lock: false)
    a = tok(client, "admin02")
    alerts = client.get("/alerts", headers=a).json()["items"]
    r7 = [x for x in alerts if x["rule_id"] == "R7"]
    assert r7 and r7[0]["severity"] == "critical" and r7[0]["username"] == "admin01"
    audit = client.get("/audit?username=admin01&action=customer.export", headers=a).json()["items"]
    assert [x["result"] for x in audit] == ["blocked"]  # 성공한 내보내기 기록이 없다
    assert client.get("/audit?action=response.warn", headers=a).json()["count"] >= 1


def test_normal_usage_not_locked(client):
    h = tok(client, "agent01")
    for p in range(1, 4):  # 150건
        assert client.get(f"/customers?page={p}&size=50", headers=h).status_code == 200
    assert status_of("agent01") == "active"


def test_unlock_flow_resets_monitoring(client):
    lock_via_repeated_bulk(client)
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
