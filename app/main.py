import json
from datetime import datetime, timedelta, timezone
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import Depends, FastAPI, HTTPException, Query, Request
from fastapi.responses import FileResponse
from pydantic import BaseModel

from app import config, masking, quota, response
from app.stats import build_stats
from app.audit import write_audit
from app.db import get_db, init_db
from app import totp
from app.security import (authenticated_user, client_ip, create_token, current_user, require_roles,
                          verify_password)

EXPORT_MAX = 1000


@asynccontextmanager
async def lifespan(_app):
    init_db()
    response.reset()
    yield


app = FastAPI(title="Defense-follow: 내부자 정보유출 방어 모의 시스템", lifespan=lifespan)


class LoginIn(BaseModel):
    username: str
    password: str


def _touch_decoys(db, user, ip, rows, resource):
    """반환하려는 행에 허니토큰(미끼 고객)이 있으면 별도 감사 이벤트를 남긴다 (규칙 R10이 즉시 대응)."""
    ids = [r["id"] for r in rows if r["decoy"]]
    if ids:
        write_audit(db, user, "honeytoken.access", resource, f"decoy ids={ids[:10]}", ip, "ok")
        db.commit()


def _scope(user):
    """상담원은 본인 담당 고객만, 관리자는 전체."""
    if user["role"] == "agent":
        return "assigned_agent_id=?", [user["id"]]
    return "1=1", []


def _login_throttled(db, username, ip):
    """최근 실패 로그인 횟수로 이 (아이디, IP) 또는 이 IP의 로그인을 일시 거부할지 판단한다."""
    cfg = quota.rules().get("login_throttle")
    if not cfg or not config.defense_enabled():
        return False
    since = (datetime.now(timezone.utc) - timedelta(minutes=cfg["window_min"])).isoformat(timespec="milliseconds")
    by_user_ip = db.execute(
        "SELECT COUNT(*) FROM audit_logs WHERE action='auth.login' AND result='failed' AND ts>=? AND ip=? AND detail=?",
        (since, ip, f"username={username}")).fetchone()[0]
    by_ip = db.execute(
        "SELECT COUNT(*) FROM audit_logs WHERE action='auth.login' AND result='failed' AND ts>=? AND ip=?",
        (since, ip)).fetchone()[0]
    return by_user_ip >= cfg["max_failures_per_user_ip"] or by_ip >= cfg["max_failures_per_ip"]


@app.post("/auth/login")
def login(body: LoginIn, request: Request, db=Depends(get_db)):
    ip = client_ip(request)
    if _login_throttled(db, body.username, ip):  # 비밀번호 검증 전에 거부한다 (아이디 존재 여부와 무관하게 같은 응답)
        write_audit(db, None, "auth.login", None, f"login throttle username={body.username}", ip, "blocked")
        db.commit()
        raise HTTPException(429, "로그인 시도가 너무 많습니다. 잠시 후 다시 시도하세요")
    user = db.execute("SELECT * FROM users WHERE username=?", (body.username,)).fetchone()
    if user is None or not verify_password(body.password, user["password_hash"]):
        write_audit(db, user, "auth.login", None, f"username={body.username}", ip, "failed")
        db.commit()
        raise HTTPException(401, "아이디 또는 비밀번호가 올바르지 않습니다")
    if user["status"] != "active":
        write_audit(db, user, "auth.login", None, f"status={user['status']}", ip, "denied")
        db.commit()
        raise HTTPException(403, "사용할 수 없는 계정입니다")
    db.execute("UPDATE users SET last_login=datetime('now') WHERE id=?", (user["id"],))
    write_audit(db, user, "auth.login", None, None, ip, "ok")
    return {"access_token": create_token(user, ip), "token_type": "bearer", "role": user["role"]}


class StepupIn(BaseModel):
    code: str
    reason: str


@app.post("/auth/stepup")
def stepup(body: StepupIn, request: Request, user=Depends(authenticated_user), db=Depends(get_db)):
    """단계적 대응으로 요구된 추가 인증. 인증 코드(TOTP)와 사유를 제출하면 요청 제한이 풀린다.
    10분 안에 3회 실패하면 계정을 잠근다 (코드 대입 공격 방지)."""
    ip = client_ip(request)
    if not user["stepup_required"]:
        return {"status": "not_required"}
    if len(body.reason.strip()) < 5:
        raise HTTPException(400, "사유(5자 이상)가 필요합니다")
    step = totp.match_step(user["totp_secret"] or "", body.code.strip())
    replayed = step is not None and step <= (user["totp_last_step"] or 0)  # 이미 쓴 코드(또는 더 이전 구간)는 재사용할 수 없다
    if step is None or replayed:
        write_audit(db, user, "auth.stepup", None, "replayed code" if replayed else "wrong code", ip, "failed")
        recent = db.execute(
            "SELECT COUNT(*) FROM audit_logs WHERE user_id=? AND action='auth.stepup' AND result='failed' AND ts>=?",
            (user["id"], (datetime.now(timezone.utc) - timedelta(minutes=10)).isoformat(timespec="milliseconds"))).fetchone()[0]
        if recent >= 3:
            db.execute("UPDATE users SET status='locked' WHERE id=?", (user["id"],))
            write_audit(db, user, "response.lock", f"user/{user['username']}", "rule=STEPUP 인증 코드 연속 실패", ip, "ok")
            db.commit()
            raise HTTPException(403, "인증 실패가 반복되어 계정이 잠겼습니다")
        db.commit()
        raise HTTPException(401, "인증 코드가 올바르지 않습니다")
    db.execute("UPDATE users SET stepup_required=0, stepup_scope=NULL, totp_last_step=? WHERE id=?", (step, user["id"]))
    write_audit(db, user, "auth.stepup", None, f"reason={body.reason.strip()}", ip, "ok")
    response.after_stepup(user["username"])
    return {"status": "verified"}


@app.get("/customers")
def list_customers(
    request: Request,
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1),
    user=Depends(require_roles("agent", "admin")),
    db=Depends(get_db),
):
    size = min(size, config.PAGE_SIZE_MAX)  # 한 번에 가져올 수 있는 양을 서버에서 제한
    size = quota.enforce(db, user, client_ip(request), "customer.list", f"page={page}&size={size}", size)  # 하드 쿼터
    where, args = _scope(user)
    rows = db.execute(
        f"SELECT * FROM customers WHERE {where} ORDER BY id LIMIT ? OFFSET ?",
        (*args, size, (page - 1) * size),
    ).fetchall()
    write_audit(db, user, "customer.list", f"page={page}&size={size}", None, client_ip(request), "ok", len(rows))
    _touch_decoys(db, user, client_ip(request), rows, f"page={page}&size={size}")
    return {"page": page, "size": size, "items": [masking.masked(r) for r in rows]}


@app.get("/customers/search")
def search_customers(
    request: Request,
    q: str = Query(..., min_length=2, max_length=30),
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1),
    user=Depends(require_roles("agent", "admin")),
    db=Depends(get_db),
):
    """이름 또는 이메일 앞부분 일치 검색. 2글자 미만은 거부해 전수 조회 용도로 쓰이는 것을 막는다."""
    size = min(size, config.PAGE_SIZE_MAX)
    where, args = _scope(user)
    clean = q.replace("%", "").replace("_", "").strip()
    if len(clean) < 2:  # 와일드카드를 제거하고 남은 검색어도 2글자 이상이어야 한다 (전수 조회 우회 방지)
        write_audit(db, user, "customer.search", f"q={q}", "query too short after sanitize", client_ip(request), "denied")
        db.commit()
        raise HTTPException(400, "검색어는 와일드카드 제외 2글자 이상이어야 합니다")
    size = quota.enforce(db, user, client_ip(request), "customer.search", f"q={q}&page={page}", size)  # 하드 쿼터
    like = clean + "%"
    rows = db.execute(
        f"SELECT * FROM customers WHERE {where} AND (name LIKE ? OR email LIKE ?) ORDER BY id LIMIT ? OFFSET ?",
        (*args, like, like, size, (page - 1) * size),
    ).fetchall()
    write_audit(db, user, "customer.search", f"q={q}&page={page}", None, client_ip(request), "ok", len(rows))
    _touch_decoys(db, user, client_ip(request), rows, f"q={q}&page={page}")
    return {"page": page, "size": size, "items": [masking.masked(r) for r in rows]}


def _serve_export(db, user, ip, limit, reason):
    """내보내기 실행부: 사전 차단(R7) → 하드 쿼터 → 마스킹된 데이터 반환. 직접 호출과 승인 후 호출이 공유한다."""
    limit = min(limit, EXPORT_MAX)
    risk = response.pre_export_check(db, user)
    if risk:  # 대량 조회 직후의 내보내기는 실행하지 않고 거부한다 (사후 차단이 아닌 사전 차단)
        write_audit(db, user, "customer.export", f"limit={limit}",
                    f"pre-block: {risk['rows_before']}건 조회 후 {risk['lookback_min']}분 이내 내보내기 시도",
                    ip, "blocked")
        db.commit()
        raise HTTPException(403, "대량 조회 직후의 내보내기는 차단되었습니다. 보안 담당자에게 문의하세요")
    limit = quota.enforce(db, user, ip, "customer.export", f"limit={limit}", limit)  # 하드 쿼터
    rows = db.execute("SELECT * FROM customers ORDER BY id LIMIT ?", (limit,)).fetchall()
    write_audit(db, user, "customer.export", f"limit={limit}", f"reason={reason.strip()}", ip, "ok", len(rows))
    _touch_decoys(db, user, ip, rows, f"export limit={limit}")
    return {"count": len(rows), "items": [masking.masked(r) for r in rows]}


def _check_reason(db, user, ip, limit, reason):
    if not reason or len(reason.strip()) < 5:
        write_audit(db, user, "customer.export", f"limit={limit}", "reason missing", ip, "denied")
        db.commit()
        raise HTTPException(400, "내보내기 사유(5자 이상)가 필요합니다")


@app.get("/customers/export")
def export_customers(
    request: Request,
    limit: int = Query(100, ge=1),
    reason: str | None = None,
    user=Depends(require_roles("admin")),
    db=Depends(get_db),
):
    """관리자 전용 내보내기. 사유 필수, 최대 1,000건, 항상 마스킹된 상태로만 내보낸다.
    승인 모드(DEFENSE_EXPORT_APPROVAL=on)에서는 직접 호출할 수 없고 요청·승인 절차를 거쳐야 한다.
    (/customers/{cid}보다 먼저 선언해야 'export'가 경로 변수로 해석되지 않는다)"""
    ip = client_ip(request)
    if config.export_approval_required():
        write_audit(db, user, "customer.export", f"limit={limit}", "approval required", ip, "denied")
        db.commit()
        raise HTTPException(403, "내보내기는 다른 관리자의 승인이 필요합니다. POST /customers/export/request 로 요청하세요")
    _check_reason(db, user, ip, limit, reason)
    return _serve_export(db, user, ip, limit, reason)


class ExportRequestIn(BaseModel):
    limit: int = 100
    reason: str


@app.post("/customers/export/request")
def export_request(body: ExportRequestIn, request: Request, user=Depends(require_roles("admin")), db=Depends(get_db)):
    """내보내기 승인 요청. 요청자와 다른 관리자가 승인해야 내려받을 수 있다."""
    ip = client_ip(request)
    _check_reason(db, user, ip, body.limit, body.reason)
    now = datetime.now(timezone.utc).isoformat(timespec="milliseconds")
    cur = db.execute("INSERT INTO export_requests(created,requester_id,limit_rows,reason) VALUES(?,?,?,?)",
                     (now, user["id"], min(max(body.limit, 1), EXPORT_MAX), body.reason.strip()))
    write_audit(db, user, "export.request", f"export_request/{cur.lastrowid}", f"limit={body.limit} reason={body.reason.strip()}", ip, "ok")
    return {"id": cur.lastrowid, "status": "pending"}


@app.get("/admin/export-requests")
def export_requests(request: Request, user=Depends(require_roles("admin")), db=Depends(get_db)):
    rows = db.execute(
        "SELECT e.id, e.created, u.username AS requester, e.limit_rows, e.reason, e.status FROM export_requests e "
        "JOIN users u ON u.id=e.requester_id ORDER BY e.id DESC LIMIT 50").fetchall()
    return {"count": len(rows), "items": [dict(r) for r in rows]}


def _decide_export(rid, request, user, db, approve):
    ip = client_ip(request)
    req = db.execute("SELECT * FROM export_requests WHERE id=?", (rid,)).fetchone()
    if req is None:
        raise HTTPException(404, "요청을 찾을 수 없습니다")
    if req["status"] != "pending":
        raise HTTPException(409, "대기 중인 요청만 처리할 수 있습니다")
    if req["requester_id"] == user["id"]:  # 본인 요청은 본인이 승인할 수 없다 (2인 원칙)
        write_audit(db, user, "export.approve", f"export_request/{rid}", "self approval", ip, "denied")
        db.commit()
        raise HTTPException(403, "본인의 요청은 승인할 수 없습니다")
    status = "approved" if approve else "rejected"
    db.execute("UPDATE export_requests SET status=?, approver_id=?, decided=? WHERE id=?",
               (status, user["id"], datetime.now(timezone.utc).isoformat(timespec="milliseconds"), rid))
    write_audit(db, user, "export.approve" if approve else "export.reject", f"export_request/{rid}", None, ip, "ok")
    return {"id": rid, "status": status}


@app.post("/admin/export-requests/{rid}/approve")
def approve_export(rid: int, request: Request, user=Depends(require_roles("admin")), db=Depends(get_db)):
    return _decide_export(rid, request, user, db, True)


@app.post("/admin/export-requests/{rid}/reject")
def reject_export(rid: int, request: Request, user=Depends(require_roles("admin")), db=Depends(get_db)):
    return _decide_export(rid, request, user, db, False)


@app.get("/customers/export/{rid}")
def download_export(rid: int, request: Request, user=Depends(require_roles("admin")), db=Depends(get_db)):
    """승인된 내보내기를 요청자 본인이 한 번만, 승인 후 15분 안에 내려받는다."""
    ip = client_ip(request)
    req = db.execute("SELECT * FROM export_requests WHERE id=?", (rid,)).fetchone()
    if req is None or req["requester_id"] != user["id"]:
        write_audit(db, user, "customer.export", f"export_request/{rid}", "not your request", ip, "denied")
        db.commit()
        raise HTTPException(404, "요청을 찾을 수 없습니다")
    if req["status"] != "approved":
        write_audit(db, user, "customer.export", f"export_request/{rid}", f"not approved: {req['status']}", ip, "denied")
        db.commit()
        raise HTTPException(403, "승인되지 않았거나 이미 사용된 요청입니다")
    decided = datetime.fromisoformat(req["decided"])
    if datetime.now(timezone.utc) - decided > timedelta(minutes=config.EXPORT_APPROVAL_TTL_MIN):
        db.execute("UPDATE export_requests SET status='expired' WHERE id=?", (rid,))
        write_audit(db, user, "customer.export", f"export_request/{rid}", "approval expired", ip, "denied")
        db.commit()
        raise HTTPException(403, "승인이 만료되었습니다. 다시 요청하세요")
    db.execute("UPDATE export_requests SET status='used' WHERE id=?", (rid,))
    db.commit()
    return _serve_export(db, user, ip, req["limit_rows"], req["reason"])


@app.get("/customers/{cid}")
def get_customer(
    cid: int,
    request: Request,
    unmask: bool = False,
    reason: str | None = None,
    user=Depends(require_roles("agent", "admin")),
    db=Depends(get_db),
):
    ip = client_ip(request)
    row = db.execute("SELECT * FROM customers WHERE id=?", (cid,)).fetchone()
    if row is None:
        raise HTTPException(404, "고객을 찾을 수 없습니다")
    if user["role"] == "agent" and row["assigned_agent_id"] != user["id"]:
        write_audit(db, user, "customer.view", f"customer/{cid}", "not assigned", ip, "denied")
        db.commit()
        _touch_decoys(db, user, ip, [row], f"customer/{cid}")  # 범위 밖 ID를 건드리다 미끼를 만나면 즉시 대응
        raise HTTPException(403, "담당 고객이 아닙니다")
    quota.enforce(db, user, ip, "customer.unmask" if unmask else "customer.view", f"customer/{cid}", 1)  # 하드 쿼터
    if unmask:
        if user["role"] != "admin":
            write_audit(db, user, "customer.unmask", f"customer/{cid}", "role not allowed", ip, "denied")
            db.commit()
            raise HTTPException(403, "마스킹 해제 권한이 없습니다")
        if not reason or len(reason.strip()) < 5:
            write_audit(db, user, "customer.unmask", f"customer/{cid}", "reason missing", ip, "denied")
            db.commit()
            raise HTTPException(400, "마스킹 해제 사유(5자 이상)가 필요합니다")
        write_audit(db, user, "customer.unmask", f"customer/{cid}", f"reason={reason.strip()}", ip, "ok", 1)
        return masking.full(row)
    write_audit(db, user, "customer.view", f"customer/{cid}", None, ip, "ok", 1)
    _touch_decoys(db, user, ip, [row], f"customer/{cid}")
    return masking.masked(row)


@app.get("/audit")
def query_audit(
    request: Request,
    username: str | None = None,
    action: str | None = None,
    result: str | None = None,
    limit: int = Query(50, ge=1),
    user=Depends(require_roles("admin")),
    db=Depends(get_db),
):
    limit = min(limit, 200)
    conds, args = [], []
    for col, val in (("username", username), ("action", action), ("result", result)):
        if val:
            conds.append(f"{col}=?")
            args.append(val)
    where = "WHERE " + " AND ".join(conds) if conds else ""
    rows = db.execute(f"SELECT * FROM audit_logs {where} ORDER BY id DESC LIMIT ?", (*args, limit)).fetchall()
    write_audit(db, user, "audit.view", None, f"filters={username},{action},{result}", client_ip(request), "ok", len(rows))
    return {"count": len(rows), "items": [dict(r) for r in rows]}


@app.get("/alerts")
def list_alerts(
    request: Request,
    rule_id: str | None = None,
    severity: str | None = None,
    limit: int = Query(50, ge=1),
    user=Depends(require_roles("admin")),
    db=Depends(get_db),
):
    limit = min(limit, 200)
    conds, args = [], []
    for col, val in (("rule_id", rule_id), ("severity", severity)):
        if val:
            conds.append(f"{col}=?")
            args.append(val)
    where = "WHERE " + " AND ".join(conds) if conds else ""
    rows = db.execute(f"SELECT * FROM alerts {where} ORDER BY id DESC LIMIT ?", (*args, limit)).fetchall()
    write_audit(db, user, "alert.view", None, None, client_ip(request), "ok", len(rows))
    items = []
    for r in rows:
        d = dict(r)
        d["detail"] = json.loads(d["detail"])
        items.append(d)
    return {"count": len(items), "items": items}


@app.post("/admin/users/{username}/unlock")
def unlock_user(
    username: str,
    request: Request,
    user=Depends(require_roles("admin")),
    db=Depends(get_db),
):
    """자동 잠금된 계정을 해제한다. 휴면·퇴사(dormant) 계정은 여기서 복구할 수 없다."""
    target = db.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
    if target is None:
        raise HTTPException(404, "사용자를 찾을 수 없습니다")
    if target["status"] != "locked":
        raise HTTPException(409, "잠금 상태의 계정만 해제할 수 있습니다")
    db.execute("UPDATE users SET status='active', stepup_required=0, stepup_scope=NULL WHERE id=?", (target["id"],))
    write_audit(db, user, "admin.unlock", f"user/{username}", None, client_ip(request), "ok")
    response.forget(username)
    return {"username": username, "status": "active"}


@app.get("/stats")
def stats(
    window_min: int = Query(60, ge=5, le=240),
    user=Depends(require_roles("admin")),
    db=Depends(get_db),
):
    """대시보드 집계. 자동 새로고침으로 자주 호출되므로 감사 로그에 남기지 않는다."""
    return build_stats(db, window_min)


@app.get("/dashboard", include_in_schema=False)
def dashboard():
    # 화면 자체에는 데이터가 없다. 로그인한 admin의 토큰으로 /stats를 호출해 채운다.
    return FileResponse(Path(__file__).parent / "static" / "dashboard.html")


@app.get("/report", include_in_schema=False)
def report():
    """6일차 방어 전후 비교 보고서 (scripts/benchmark.py가 생성). 고객 정보는 포함하지 않는다."""
    path = Path(__file__).resolve().parent.parent / "docs" / "benchmark.html"
    if not path.exists():
        raise HTTPException(404, "보고서가 아직 없습니다. scripts/benchmark.py를 먼저 실행하세요")
    return FileResponse(path)


@app.get("/me")
def me(user=Depends(current_user)):
    return {"username": user["username"], "role": user["role"], "status": user["status"]}
