"""서버 하드 쿼터 검증: 느리게 읽어도 유출되는 최대 건수가 쿼터로 고정된다."""
import importlib
from datetime import datetime, timedelta, timezone

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


def preload(username, rows_total, hours_ago=3):
    """이미 이만큼 조회했다고 감사 로그에 직접 기록한다 (50건 단위, 1분 간격, 모두 과거 시각).
    hours_ago는 가장 오래된 기록의 시각이다. 최근 30분 안의 조회는 만들지 않아 반출 사전 차단(R7)과 섞이지 않는다."""
    from app import db as dbm
    conn = dbm.connect()
    u = conn.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
    t0 = datetime.now(timezone.utc) - timedelta(hours=hours_ago)
    chunks = [50] * (rows_total // 50) + ([rows_total % 50] if rows_total % 50 else [])
    for i, rows in enumerate(chunks):
        ts = (t0 + timedelta(minutes=i)).isoformat(timespec="milliseconds")
        conn.execute("INSERT INTO audit_logs(ts,user_id,username,role,action,result,rows) VALUES(?,?,?,?,?,'ok',?)",
                     (ts, u["id"], username, u["role"], "customer.list", rows))
    conn.commit()
    conn.close()


def audit_rows(sql, args=()):
    from app import db as dbm
    conn = dbm.connect()
    r = [dict(x) for x in conn.execute(sql, args)]
    conn.close()
    return r


def test_partial_then_blocked_when_quota_runs_out(client):
    preload("agent01", 1450, hours_ago=20)  # 상담원 한도 1,500건 중 1,450건 사용
    h = tok(client, "agent01")
    r = client.get("/customers?page=1&size=50", headers=h)
    assert r.status_code == 200 and len(r.json()["items"]) == 50  # 남은 50건
    r = client.get("/customers?page=2&size=50", headers=h)
    assert r.status_code == 429 and "items" not in r.json()
    blocked = audit_rows("SELECT * FROM audit_logs WHERE username='agent01' AND result='blocked'")
    assert blocked and "quota exceeded" in blocked[-1]["detail"]


def test_quota_stops_before_daily_lock_rule_for_agents(client):
    """상담원 쿼터(1,500)가 R6 잠금 기준(2,000)보다 낮아, 상담원은 잠기기 전에 쿼터에서 먼저 멈춘다."""
    preload("agent01", 1450, hours_ago=20)
    client.get("/customers?page=1&size=50", headers=tok(client, "agent01"))
    assert audit_rows("SELECT status FROM users WHERE username='agent01'")[0]["status"] == "active"


def test_request_larger_than_remaining_returns_only_remaining(client):
    preload("admin01", 1980, hours_ago=2)
    r = client.get("/customers?page=1&size=50", headers=tok(client, "admin01"))
    assert r.status_code == 200 and len(r.json()["items"]) == 20


def test_total_served_never_exceeds_quota(client):
    preload("admin01", 1900, hours_ago=2)
    h = tok(client, "admin01")
    served = 0
    for p in range(1, 10):
        r = client.get(f"/customers?page={p}&size=50", headers=h)
        if r.status_code == 200:
            served += len(r.json()["items"])
    assert served == 100  # 1,900 + 100 = 2,000 에서 멈춤


def test_old_reads_outside_window_do_not_count(client):
    preload("admin01", 1950, hours_ago=30)  # 24시간 창 밖
    r = client.get("/customers?page=1&size=50", headers=tok(client, "admin01"))
    assert r.status_code == 200 and len(r.json()["items"]) == 50


def test_agent_has_its_own_lower_limit(client):
    preload("agent01", 1500, hours_ago=3)
    r = client.get("/customers?page=1&size=20", headers=tok(client, "agent01"))
    assert r.status_code == 429


def test_search_view_and_export_are_also_limited(client):
    preload("admin01", 2000, hours_ago=3)
    h = tok(client, "admin01")
    assert client.get("/customers/search?q=김민&page=1&size=10", headers=h).status_code == 429
    assert client.get("/customers/5", headers=h).status_code == 429
    assert client.get("/customers/export?limit=10&reason=정기 점검 보고", headers=h).status_code == 429


def test_export_is_trimmed_to_remaining_quota(client):
    preload("admin01", 1960, hours_ago=3)
    r = client.get("/customers/export?limit=500&reason=정기 점검 보고", headers=tok(client, "admin01"))
    assert r.status_code == 200 and r.json()["count"] == 40


def test_quota_not_applied_when_defense_off(client, monkeypatch):
    preload("admin01", 2000, hours_ago=3)
    monkeypatch.setenv("DEFENSE_MODE", "off")
    assert client.get("/customers?page=1&size=50", headers=tok(client, "admin01")).status_code == 200


def test_quota_exceeded_attempt_raises_r9_warning_without_lock(client):
    preload("admin01", 2000, hours_ago=3)
    h = tok(client, "admin01")
    assert client.get("/customers?page=1&size=50", headers=h).status_code == 429
    alerts = audit_rows("SELECT rule_id FROM alerts WHERE username='admin01'")
    assert "R9" in [a["rule_id"] for a in alerts]
    st = audit_rows("SELECT status FROM users WHERE username='admin01'")[0]["status"]
    assert st == "active"  # 서버가 이미 거부했으므로 R9는 경고만 한다


def test_other_users_quota_is_independent(client):
    preload("admin01", 2000, hours_ago=3)
    assert client.get("/customers?page=1&size=20", headers=tok(client, "agent01")).status_code == 200


def test_benchmark_quota_column_is_min_of_detection_and_quota():
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
    import benchmark
    for e in benchmark.run_evasion(rates=(3, 10, 60)):
        assert e["quota_leaked"] == min(e["rows_leaked"], benchmark.QUOTA_AGENT)
