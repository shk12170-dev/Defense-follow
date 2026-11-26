"""보안 점검 후 보강: 로그인 스로틀(R12), TOTP 재사용 방지."""
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


def login(c, user, pw=PW):
    return c.post("/auth/login", json={"username": user, "password": pw})


def q(sql, args=()):
    from app import db as dbm
    conn = dbm.connect()
    r = [dict(x) for x in conn.execute(sql, args)]
    conn.close()
    return r


# ---------- 로그인 스로틀 ----------
def test_fifth_failure_triggers_throttle_even_with_correct_password(client):
    codes = [login(client, "agent01", "wrong-pw").status_code for _ in range(5)]
    assert codes == [401] * 5
    assert login(client, "agent01").status_code == 429  # 올바른 비밀번호도 일시 거부


def test_throttle_does_not_lock_the_account(client):
    for _ in range(6):
        login(client, "agent01", "wrong-pw")
    assert q("SELECT status FROM users WHERE username='agent01'")[0]["status"] == "active"


def test_throttle_is_per_username_and_ip(client):
    for _ in range(5):
        login(client, "agent01", "wrong-pw")
    assert login(client, "agent02").status_code == 200  # 다른 아이디는 영향 없음


def test_unknown_usernames_get_same_response_and_ip_wide_limit(client):
    codes = [login(client, f"nobody{i}", "x").status_code for i in range(20)]
    assert codes == [401] * 20
    assert login(client, "agent02").status_code == 429  # 같은 IP에서 20회 실패하면 IP 전체 일시 거부


def test_throttle_raises_r12_warning(client):
    for _ in range(6):
        login(client, "agent01", "wrong-pw")
    alerts = q("SELECT rule_id, severity FROM alerts")
    assert ("R12", "medium") in [(a["rule_id"], a["severity"]) for a in alerts]
    blocked = q("SELECT detail FROM audit_logs WHERE action='auth.login' AND result='blocked'")
    assert blocked and "login throttle" in blocked[0]["detail"]


def test_successful_logins_are_not_counted(client):
    for _ in range(10):
        assert login(client, "agent01").status_code == 200


def test_throttle_off_when_defense_off(client, monkeypatch):
    monkeypatch.setenv("DEFENSE_MODE", "off")
    for _ in range(8):
        login(client, "agent01", "wrong-pw")
    assert login(client, "agent01").status_code == 200


# ---------- TOTP 재사용 방지 ----------
def trip_stepup(client, user="agent01"):
    h = {"Authorization": "Bearer " + login(client, user).json()["access_token"]}
    for p in range(1, 8):
        client.get(f"/customers?page={p}&size=50", headers=h)
    return h


def secret(user):
    return q("SELECT totp_secret FROM users WHERE username=?", (user,))[0]["totp_secret"]


def test_used_code_cannot_be_reused(client):
    h = trip_stepup(client)
    code = totp.code_for(secret("agent01"))
    body = {"code": code, "reason": "고객 요청 처리 중 대량 조회"}
    assert client.post("/auth/stepup", json=body, headers=h).status_code == 200
    # 재인증 상태를 다시 만들어도(다른 계정 흐름 시뮬레이션) 같은 코드는 거부된다
    from app import db as dbm
    conn = dbm.connect()
    conn.execute("UPDATE users SET stepup_required=1 WHERE username='agent01'")
    conn.commit()
    conn.close()
    r = client.post("/auth/stepup", json=body, headers=h)
    assert r.status_code == 401
    audit = q("SELECT detail FROM audit_logs WHERE action='auth.stepup' AND result='failed'")
    assert audit and audit[-1]["detail"] == "replayed code"


def test_next_time_step_code_is_accepted_after_use(client):
    import time
    h = trip_stepup(client)
    s = secret("agent01")
    now = time.time()
    assert client.post("/auth/stepup", json={"code": totp.code_for(s, now - 30), "reason": "고객 요청 처리 중 대량 조회"}, headers=h).status_code == 200
    from app import db as dbm
    conn = dbm.connect()
    conn.execute("UPDATE users SET stepup_required=1 WHERE username='agent01'")
    conn.commit()
    conn.close()
    # 더 이전 구간 코드는 거부, 더 나중 구간 코드는 허용
    assert client.post("/auth/stepup", json={"code": totp.code_for(s, now - 30), "reason": "고객 요청 처리 중 대량 조회"}, headers=h).status_code == 401
    assert client.post("/auth/stepup", json={"code": totp.code_for(s, now + 30), "reason": "고객 요청 처리 중 대량 조회"}, headers=h).status_code == 200


def test_match_step_returns_counter_or_none():
    s = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
    assert totp.match_step(s, "287082", at=59) == 1  # 59초 -> 구간 1
    assert totp.match_step(s, "000000", at=59) is None
