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


def ensure_stepup(client, user, h):
    """일일 누적 규칙(R5)이 재인증을 요구했다면 통과시킨다 (쿼터 동작만 보려는 테스트용)."""
    from app import totp
    row = audit_rows("SELECT stepup_required, totp_secret FROM users WHERE username=?", (user,))[0]
    if row["stepup_required"]:
        r = client.post("/auth/stepup", json={"code": totp.code_for(row["totp_secret"]), "reason": "쿼터 시험용 재인증"}, headers=h)
        assert r.status_code == 200


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
    ensure_stepup(client, "agent01", h)  # 누적 1,500건으로 R5가 재인증을 요구함
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
        ensure_stepup(client, "admin01", h)
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


# ---------- 7일 쿼터 (다일 누적) ----------
def preload_days(username, per_day, days_ago_list):
    """각 날(며칠 전)에 per_day건을 50건씩 조회한 기록. 모두 24시간 밖이라 일일 쿼터·R5에는 걸리지 않는다."""
    from app import db as dbm
    conn = dbm.connect()
    u = conn.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
    for n in days_ago_list:
        t0 = datetime.now(timezone.utc) - timedelta(days=n)
        for i in range(per_day // 50):
            ts = (t0 + timedelta(minutes=i)).isoformat(timespec="milliseconds")
            conn.execute("INSERT INTO audit_logs(ts,user_id,username,role,action,result,rows) VALUES(?,?,?,?,?,'ok',50)",
                         (ts, u["id"], username, u["role"], "customer.list"))
    conn.commit()
    conn.close()


def test_weekly_quota_stops_slow_daily_accumulation(client):
    preload_days("agent01", 1400, [2, 3, 4, 5, 6])  # 5일 동안 매일 1,400건 = 7,000건 (일일 한도 1,500 미만)
    r = client.get("/customers?page=1&size=20", headers=tok(client, "agent01"))
    assert r.status_code == 429
    blocked = audit_rows("SELECT detail FROM audit_logs WHERE username='agent01' AND result='blocked'")
    assert "168시간" in blocked[-1]["detail"]  # 하루 한도가 아니라 7일 한도에 걸림


def test_weekly_quota_returns_only_the_remaining_part(client):
    preload_days("agent01", 1380, [2, 3, 4, 5, 6])  # 6,900건 사용, 7일 한도 7,000
    r = client.get("/customers?page=1&size=50", headers=tok(client, "agent01"))
    assert r.status_code == 200 and len(r.json()["items"]) <= 50
    # 남은 100건 중 이번 요청이 가져간 만큼을 제외하고는 다음 요청에서 소진된다
    served = len(r.json()["items"])
    r2 = client.get("/customers?page=2&size=50", headers=tok(client, "agent01"))
    assert r2.status_code == (200 if served < 100 else 429)


def test_normal_week_is_not_blocked(client):
    preload_days("agent01", 1000, [2, 3, 4, 5, 6])  # 하루 1,000건씩 5일 = 5,000건 (정상 범위)
    assert client.get("/customers?page=1&size=20", headers=tok(client, "agent01")).status_code == 200


def test_window_remaining_picks_tightest_window():
    from app import quota
    assert quota.remaining([(1500, 100, 24), (7000, 6900, 168)]) == (100, 6900, 7000, 168)
    assert quota.remaining([(1500, 1400, 24), (7000, 100, 168)]) == (100, 1400, 1500, 24)
    assert quota.remaining([]) is None


def test_multiday_benchmark_weekly_cap_reduces_leak():
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
    import benchmark
    m = {x["per_day"]: x for x in benchmark.run_multiday()}
    assert m[1450]["quota_24h"] == m[1450]["no_quota"] == 20300  # 일일 쿼터만으로는 못 막음
    assert m[1450]["quota_24h_7d"] < 0.75 * m[1450]["no_quota"]  # 7일 쿼터로 크게 감소
    assert m[700]["quota_24h_7d"] == m[700]["no_quota"]  # 정상 업무량은 영향 없음
