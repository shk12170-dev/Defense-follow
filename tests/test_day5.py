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


def test_stats_requires_admin(client):
    assert client.get("/stats").status_code == 401
    assert client.get("/stats", headers=tok(client, "agent01")).status_code == 403


def test_stats_empty_state(client):
    s = client.get("/stats", headers=tok(client, "admin02")).json()
    assert s["totals"] == {"alerts": 0, "alerts_high": 0, "locked": 0, "stepup": 0, "rows_window": 0}
    assert len(s["buckets"]) == 12 and s["threshold"] == 300


def test_stats_reflects_attack(client):
    h = tok(client, "agent01")
    for p in range(1, 8):
        client.get(f"/customers?page={p}&size=50", headers=h)
    s = client.get("/stats", headers=tok(client, "admin02")).json()
    assert s["totals"]["stepup"] == 1 and s["totals"]["alerts_high"] >= 1  # R1 첫 발동은 재인증 요구
    assert s["stepup_users"][0]["username"] == "agent01" and s["totals"]["locked"] == 0
    assert s["top_users"][0] == {"username": "agent01", "rows": 300}
    assert sum(b["rows"] for b in s["buckets"]) == 300
    assert any(r["rule_id"] == "R1" for r in s["by_rule"])
    assert any(e["action"] == "response.stepup" for e in s["recent_events"])


def test_stats_does_not_write_audit_log(client):
    a = tok(client, "admin02")
    before = len(client.get("/audit?limit=200", headers=a).json()["items"])
    for _ in range(3):
        client.get("/stats", headers=a)
    after = len(client.get("/audit?limit=200", headers=a).json()["items"])
    assert after == before + 1  # 위 /audit 호출 자체의 audit.view 1건만 증가


def test_dashboard_page_served_and_escapes(client):
    r = client.get("/dashboard")
    assert r.status_code == 200 and "보안 관제 대시보드" in r.text
    assert "const esc" in r.text  # 모든 동적 값은 esc()를 거친다
    assert "/stats" in r.text


def test_hostile_username_stored_verbatim_for_client_escaping(client):
    payload = "<img src=x onerror=alert(1)>"
    client.post("/auth/login", json={"username": payload, "password": "x"})
    s = client.get("/stats", headers=tok(client, "admin02")).json()
    # API는 원문 그대로 반환하고, 화면 렌더링에서 esc()로 무해화한다
    assert any(payload in (e["detail"] or "") for e in s["recent_events"])
