"""쿼터 강화 검증: 유형별 한도, 10분 한도, 재인증 후 축소, 마스킹 해제 별도 한도, 프로필."""
import importlib
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from app import quota

PW = "Demo#2026pw"


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("DEFENSE_DB", str(tmp_path / "t.db"))
    monkeypatch.setenv("DEFENSE_AUDIT_LOG", str(tmp_path / "audit.jsonl"))
    monkeypatch.setenv("DEFENSE_MODE", "on")
    monkeypatch.setattr(quota, "_rules", None)  # conftest가 끈 유형별 한도·재인증 후 축소를 실제 설정으로 되돌린다
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
    return {"Authorization": "Bearer " + c.post("/auth/login", json={"username": user, "password": PW}).json()["access_token"]}


def q(sql, args=()):
    from app import db as dbm
    conn = dbm.connect()
    r = [dict(x) for x in conn.execute(sql, args)]
    conn.close()
    return r


def preload(username, action, rows_total, minutes_ago=5, result="ok", chunk=10):
    """audit_logs에 이미 이만큼 처리했다는 기록을 직접 남긴다(최근 minutes_ago분 이내)."""
    from app import db as dbm
    conn = dbm.connect()
    u = conn.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
    t0 = datetime.now(timezone.utc) - timedelta(minutes=minutes_ago)
    left, i = rows_total, 0
    while left > 0:
        n = min(chunk, left)
        ts = (t0 + timedelta(seconds=i)).isoformat(timespec="milliseconds")
        conn.execute("INSERT INTO audit_logs(ts,user_id,username,role,action,result,rows) VALUES(?,?,?,?,?,?,?)",
                     (ts, u["id"], username, u["role"], action, result, n))
        left -= n
        i += 1
    conn.commit()
    conn.close()


def search(c, h, size=20):
    return c.get(f"/customers/search?q=김민&page=1&size={size}", headers=h)


# ---------- 유형별 + 10분 한도 ----------
def test_browse_10min_cap_blocks_when_used_up(client):
    preload("agent01", "customer.search", 100, minutes_ago=3)  # 상세·검색 10분 한도 100건 소진
    assert search(client, tok(client, "agent01")).status_code == 429
    blocked = q("SELECT detail FROM audit_logs WHERE username='agent01' AND result='blocked'")
    assert "10분" in blocked[-1]["detail"] and "상세·검색" in blocked[-1]["detail"]


def test_browse_10min_cap_older_usage_does_not_count(client):
    preload("agent01", "customer.search", 100, minutes_ago=30)  # 10분 창 밖 (24시간 한도 500건 안)
    assert search(client, tok(client, "agent01")).status_code == 200


def test_list_10min_cap_stops_bulk_paging_before_r1(client):
    h = tok(client, "agent01")
    codes = [client.get(f"/customers?page={p}&size=50", headers=h).status_code for p in range(1, 8)]
    assert codes[:4] == [200] * 4 and set(codes[4:]) == {429}  # 목록 10분 한도 200건
    assert q("SELECT status, stepup_required FROM users WHERE username='agent01'")[0] == {"status": "active", "stepup_required": 0}
    assert "R9" in [a["rule_id"] for a in q("SELECT rule_id FROM alerts")]  # 한도 초과 시도로 경고


def test_browse_cap_does_not_use_up_the_list_allowance(client):
    preload("agent01", "customer.search", 100, minutes_ago=3)  # 상세·검색만 소진
    assert client.get("/customers?page=1&size=20", headers=tok(client, "agent01")).status_code == 200  # 목록은 별도


def test_daily_browse_cap(client):
    preload("agent01", "customer.view", 500, minutes_ago=600)  # 10분 창 밖, 24시간 창 안
    assert search(client, tok(client, "agent01")).status_code == 429


def test_unmask_has_its_own_small_daily_cap(client):
    preload("admin01", "customer.unmask", 20, minutes_ago=600)
    h = tok(client, "admin01")
    assert client.get("/customers/5?unmask=true&reason=본인 확인 업무", headers=h).status_code == 429
    assert client.get("/customers/5", headers=h).status_code == 200  # 마스킹된 일반 조회는 영향 없음


# ---------- 재인증 후 한도 축소 ----------
def stepup_row(username):
    from app import db as dbm
    conn = dbm.connect()
    u = conn.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
    ts = (datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat(timespec="milliseconds")
    conn.execute("INSERT INTO audit_logs(ts,user_id,username,role,action,result,rows) VALUES(?,?,?,?,?,'ok',0)",
                 (ts, u["id"], username, u["role"], "auth.stepup"))
    conn.commit()
    conn.close()


def test_stepup_penalty_blocks_what_was_still_allowed_before(client):
    preload("agent01", "customer.list", 460, minutes_ago=300)  # 일일 한도 900건 중 460건 (재인증 후 한도 450건)
    h = tok(client, "agent01")
    assert client.get("/customers?page=1&size=20", headers=h).status_code == 200
    stepup_row("agent01")
    r = client.get("/customers?page=2&size=20", headers=h)
    assert r.status_code == 429  # 480건 사용 > 450건
    assert quota_info_cap("agent01") == 450


def quota_info_cap(username):
    d = q("SELECT detail FROM audit_logs WHERE username=? AND result='blocked' ORDER BY id DESC LIMIT 1", (username,))[0]["detail"]
    return int(d.split("/")[1].split("건")[0])


def test_no_penalty_without_a_stepup(client):
    preload("agent01", "customer.list", 500, minutes_ago=300)
    assert client.get("/customers?page=1&size=20", headers=tok(client, "agent01")).status_code == 200


# ---------- 프로필 ----------
def test_strict_profile_is_much_tighter(client, monkeypatch):
    monkeypatch.setenv("DEFENSE_QUOTA_PROFILE", "strict")
    h = tok(client, "agent01")
    codes = [client.get(f"/customers?page={p}&size=50", headers=h).status_code for p in range(1, 5)]
    assert codes == [200, 200, 429, 429]  # 목록 10분 한도 100건


def test_specs_and_pure_evaluation(monkeypatch):
    monkeypatch.setattr(quota, "_rules", None)
    sp = quota.specs("agent", "customer.list")
    assert ("10분, 목록", 10, frozenset(["customer.list"]), 200) in sp
    assert not any(s[3] == 20 for s in sp)  # 마스킹 해제 한도는 목록에 적용되지 않는다
    assert any(s[3] == 20 for s in quota.specs("admin", "customer.unmask"))
    used = lambda minutes, acts: 150 if minutes == 10 else 0  # noqa: E731
    n, info = quota.evaluate(sp, used, 100)
    assert n == 50 and info["label"].startswith("10분")
    n, info = quota.evaluate(sp, used, 100, factor=0.5)
    assert n == 0  # 한도 100, 이미 150


def test_quota_off_when_defense_off(client, monkeypatch):
    monkeypatch.setenv("DEFENSE_MODE", "off")
    preload("agent01", "customer.search", 500, minutes_ago=3)
    assert search(client, tok(client, "agent01")).status_code == 200


# ---------- 측정 시뮬레이션 (scripts/quota_study.py) ----------
@pytest.fixture(scope="module")
def study_env():
    import sys
    from pathlib import Path
    scripts = str(Path(__file__).resolve().parent.parent / "scripts")
    if scripts not in sys.path:
        sys.path.insert(0, scripts)
    import benchmark
    import quota_study
    from app.detection import load_rules
    return quota_study, benchmark.normal_events(), load_rules()["quota"]


def test_study_standard_profile_has_few_false_positives(study_env):
    qs, ev, qcfg = study_env
    n = qs.normal_impact(quota.profile_config(qcfg, "standard"), ev)
    assert n["agent_blocked_days"] / n["agent_days"] <= 0.10 and n["admin_blocked_days"] == 0


def test_study_browse_caps_alone_never_block_normal_work(study_env):
    qs, ev, _ = study_env
    n = qs.normal_impact(qs.make_cfg(browse10=(100, 100), browse_day=(500, 500), unmask_day=20), ev)
    assert n["agent_blocked_days"] <= 2 and n["admin_blocked_days"] == 0


def test_study_strict_profile_costs_list_heavy_work_but_not_browse_only_work(study_env):
    qs, ev, qcfg = study_env
    strict = quota.profile_config(qcfg, "strict")
    heavy = qs.normal_impact(strict, ev)
    light = qs.normal_impact(strict, qs.no_list_events(ev))
    assert heavy["agent_blocked_days"] / heavy["agent_days"] > 0.5
    assert light["agent_blocked_days"] / light["agent_days"] <= 0.05


def test_study_leaks_shrink_with_profiles(study_env):
    qs, ev, qcfg = study_env
    base = qs.study({"base": qs.make_cfg()}, ev)[0]
    std = qs.study({"std": quota.profile_config(qcfg, "standard")}, ev)[0]
    strict = qs.study({"strict": quota.profile_config(qcfg, "strict")}, ev)[0]
    assert base["s1_agent_list"] > std["s1_agent_list"] > strict["s1_agent_list"]
    assert base["day_agent"] > std["day_agent"] > strict["day_agent"]
    assert std["day_agent_after_stepup"] <= std["day_agent"] / 2 + 50  # 재인증 후 한도 절반 수준
    assert strict["d14_1450"] < base["d14_1450"]


def test_server_and_simulation_agree_on_list_cap(client):
    from scripts import quota_study  # noqa: F401  (임포트 가능 확인)
    h = tok(client, "agent01")
    served = sum(len(client.get(f"/customers?page={p}&size=50", headers=h).json().get("items", [])) for p in range(1, 8))
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
    import quota_study as qs
    from app.detection import load_rules
    sim = qs.burst_leak(quota.profile_config(load_rules()["quota"], "standard"), "agent", "customer.list")
    assert served == sim == 200
