import hashlib
import hmac
import os
from datetime import datetime, timedelta, timezone

import jwt
from fastapi import Depends, HTTPException, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from app import config
from app.audit import write_audit
from app.db import get_db

_bearer = HTTPBearer(auto_error=False)
_ITER = 200_000


def hash_password(pw):
    salt = os.urandom(16)
    dk = hashlib.pbkdf2_hmac("sha256", pw.encode(), salt, _ITER)
    return f"{salt.hex()}${dk.hex()}"


def verify_password(pw, stored):
    salt_hex, dk_hex = stored.split("$")
    dk = hashlib.pbkdf2_hmac("sha256", pw.encode(), bytes.fromhex(salt_hex), _ITER)
    return hmac.compare_digest(dk.hex(), dk_hex)


def create_token(user):
    now = datetime.now(timezone.utc)
    payload = {
        "sub": str(user["id"]),
        "role": user["role"],
        "iat": now,
        "exp": now + timedelta(minutes=config.JWT_TTL_MIN),
    }
    return jwt.encode(payload, config.JWT_SECRET, algorithm=config.JWT_ALG)


def client_ip(request: Request):
    if config.trusted_proxy():
        xff = request.headers.get("x-forwarded-for", "")
        first = xff.split(",")[0].strip()
        if first:
            return first[:64]
    return request.client.host if request.client else "unknown"


_STEPUP_ALLOWED_PATHS = {"/auth/stepup", "/me"}


def authenticated_user(
    request: Request,
    cred: HTTPAuthorizationCredentials | None = Depends(_bearer),
    db=Depends(get_db),
):
    """토큰과 계정 상태를 확인한다. 재인증 요구 여부는 확인하지 않는다(재인증 엔드포인트용)."""
    ip = client_ip(request)
    if cred is None:
        write_audit(db, None, "auth.token", request.url.path, "missing token", ip, "denied")
        db.commit()
        raise HTTPException(401, "인증이 필요합니다")
    try:
        data = jwt.decode(cred.credentials, config.JWT_SECRET, algorithms=[config.JWT_ALG])
    except jwt.PyJWTError:
        write_audit(db, None, "auth.token", request.url.path, "invalid token", ip, "denied")
        db.commit()
        raise HTTPException(401, "유효하지 않은 토큰입니다")
    user = db.execute("SELECT * FROM users WHERE id=?", (int(data["sub"]),)).fetchone()
    # 토큰이 유효해도 DB의 현재 상태를 항상 재확인한다 (잠금·휴면 즉시 반영)
    if user is None or user["status"] != "active":
        write_audit(db, user, "auth.token", request.url.path, "inactive account", ip, "denied")
        db.commit()
        raise HTTPException(403, "비활성 계정입니다")
    return user


def current_user(
    request: Request,
    user=Depends(authenticated_user),
    db=Depends(get_db),
):
    """일반 엔드포인트용: 단계적 대응으로 재인증이 요구된 계정은 재인증 전까지 요청을 거부한다(428)."""
    if user["stepup_required"] and request.url.path not in _STEPUP_ALLOWED_PATHS:
        write_audit(db, user, "auth.token", request.url.path, "stepup required", client_ip(request), "denied")
        db.commit()
        raise HTTPException(428, "추가 인증이 필요합니다. POST /auth/stepup 으로 인증 코드와 사유를 제출하세요")
    return user


def require_roles(*roles):
    def checker(request: Request, user=Depends(current_user), db=Depends(get_db)):
        if user["role"] not in roles:
            write_audit(db, user, "authz.role", request.url.path, f"need {roles}", client_ip(request), "denied")
            db.commit()
            raise HTTPException(403, "권한이 없습니다")
        return user

    return checker
