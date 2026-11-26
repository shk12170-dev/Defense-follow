"""내보내기 2인 승인(옵션 모드) 검증."""
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
    monkeypatch.setenv("DEFENSE_EXPORT_APPROVAL", "on")
    from app import config
    importlib.reload(config)
    from app import audit, response
    audit._last_hash.clear()
    response.reset()
    from scripts import seed
    importlib.reload(seed)
    seed.main(n_customers=2000)
    from app import main
    with TestClient(main.app) as c:
        yield c


def tok(c, user):
    r = c.post("/auth/login", json={"username": user, "password": PW})
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


def request_export(c, h, limit=50, reason="월간 보고서 작성용"):
    return c.post("/customers/export/request", json={"limit": limit, "reason": reason}, headers=h)


def test_direct_export_is_refused_in_approval_mode(client):
    r = client.get("/customers/export?limit=10&reason=직접 호출 시도", headers=tok(client, "admin01"))
    assert r.status_code == 403 and "승인" in r.json()["detail"]


def test_full_flow_two_admins_and_single_use(client):
    a1, a2 = tok(client, "admin01"), tok(client, "admin02")
    rid = request_export(client, a1).json()["id"]
    assert client.get(f"/customers/export/{rid}", headers=a1).status_code == 403  # 승인 전
    assert client.post(f"/admin/export-requests/{rid}/approve", headers=a2).json()["status"] == "approved"
    r = client.get(f"/customers/export/{rid}", headers=a1)
    assert r.status_code == 200 and r.json()["count"] == 50
    assert client.get(f"/customers/export/{rid}", headers=a1).status_code == 403  # 한 번만


def test_requester_cannot_approve_own_request(client):
    a1 = tok(client, "admin01")
    rid = request_export(client, a1).json()["id"]
    r = client.post(f"/admin/export-requests/{rid}/approve", headers=a1)
    assert r.status_code == 403
    audit = client.get("/audit?action=export.approve", headers=tok(client, "admin02")).json()["items"]
    assert audit and audit[0]["result"] == "denied" and "self approval" in audit[0]["detail"]


def test_only_the_requester_can_download(client):
    a1, a2 = tok(client, "admin01"), tok(client, "admin02")
    rid = request_export(client, a1).json()["id"]
    client.post(f"/admin/export-requests/{rid}/approve", headers=a2)
    assert client.get(f"/customers/export/{rid}", headers=a2).status_code == 404


def test_reject_and_agents_have_no_access(client):
    a1, a2 = tok(client, "admin01"), tok(client, "admin02")
    rid = request_export(client, a1).json()["id"]
    assert client.post(f"/admin/export-requests/{rid}/reject", headers=a2).json()["status"] == "rejected"
    assert client.get(f"/customers/export/{rid}", headers=a1).status_code == 403
    ag = tok(client, "agent01")
    assert request_export(client, ag).status_code == 403
    assert client.post(f"/admin/export-requests/{rid}/approve", headers=ag).status_code == 403


def test_reason_required_and_expired_approval(client):
    a1, a2 = tok(client, "admin01"), tok(client, "admin02")
    assert request_export(client, a1, reason="짧음").status_code == 400
    rid = request_export(client, a1).json()["id"]
    client.post(f"/admin/export-requests/{rid}/approve", headers=a2)
    from app import db as dbm
    conn = dbm.connect()
    old = (datetime.now(timezone.utc) - timedelta(minutes=30)).isoformat(timespec="milliseconds")
    conn.execute("UPDATE export_requests SET decided=? WHERE id=?", (old, rid))
    conn.commit()
    conn.close()
    r = client.get(f"/customers/export/{rid}", headers=a1)
    assert r.status_code == 403 and "만료" in r.json()["detail"]


def test_approved_export_still_goes_through_preblock_and_quota(client):
    a1, a2 = tok(client, "admin01"), tok(client, "admin02")
    for p in range(1, 5):  # 직전 200건 조회 (R7 기준)
        client.get(f"/customers?page={p}&size=50", headers=a1)
    rid = request_export(client, a1).json()["id"]
    client.post(f"/admin/export-requests/{rid}/approve", headers=a2)
    r = client.get(f"/customers/export/{rid}", headers=a1)
    assert r.status_code == 403 and "차단" in r.json()["detail"]  # 승인이 있어도 사전 차단은 유지


def test_listing_shows_requests_to_admins(client):
    a1 = tok(client, "admin01")
    request_export(client, a1)
    items = client.get("/admin/export-requests", headers=tok(client, "admin02")).json()["items"]
    assert items and items[0]["requester"] == "admin01" and items[0]["status"] == "pending"


def test_direct_export_still_works_when_mode_off(client, monkeypatch):
    monkeypatch.setenv("DEFENSE_EXPORT_APPROVAL", "off")
    r = client.get("/customers/export?limit=10&reason=기본 모드 호출", headers=tok(client, "admin01"))
    assert r.status_code == 200
