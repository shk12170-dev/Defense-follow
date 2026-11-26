import json
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import Depends, FastAPI, HTTPException, Query, Request
from fastapi.responses import FileResponse
from pydantic import BaseModel

from app import config, masking, quota, response
from app.stats import build_stats
from app.audit import write_audit
from app.db import get_db, init_db
from app.security import (client_ip, create_token, current_user, require_roles,
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


def _scope(user):
    """상담원은 본인 담당 고객만, 관리자는 전체."""
    if user["role"] == "agent":
        return "assigned_agent_id=?", [user["id"]]
    return "1=1", []


@app.post("/auth/login")
def login(body: LoginIn, request: Request, db=Depends(get_db)):
    ip = client_ip(request)
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
    return {"access_token": create_token(user), "token_type": "bearer", "role": user["role"]}


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
    return {"page": page, "size": size, "items": [masking.masked(r) for r in rows]}


@app.get("/customers/export")
def export_customers(
    request: Request,
    limit: int = Query(100, ge=1),
    reason: str | None = None,
    user=Depends(require_roles("admin")),
    db=Depends(get_db),
):
    """관리자 전용 내보내기. 사유 필수, 최대 1,000건, 항상 마스킹된 상태로만 내보낸다.
    (/customers/{cid}보다 먼저 선언해야 'export'가 경로 변수로 해석되지 않는다)"""
    ip = client_ip(request)
    if not reason or len(reason.strip()) < 5:
        write_audit(db, user, "customer.export", f"limit={limit}", "reason missing", ip, "denied")
        db.commit()
        raise HTTPException(400, "내보내기 사유(5자 이상)가 필요합니다")
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
    return {"count": len(rows), "items": [masking.masked(r) for r in rows]}


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
    db.execute("UPDATE users SET status='active' WHERE id=?", (target["id"],))
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
