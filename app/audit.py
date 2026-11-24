import hashlib
import json
import threading
from datetime import datetime, timezone

from app import config

_lock = threading.Lock()
_hooks = []  # 감사 이벤트가 기록될 때마다 호출되는 콜백 (실시간 탐지·대응이 등록)
_last_hash = {}  # 로그 파일 경로 -> 마지막 해시 (프로세스 내 캐시)
GENESIS = "0" * 64


def _chain_hash(prev, body):
    return hashlib.sha256((prev + json.dumps(body, ensure_ascii=False, sort_keys=True)).encode()).hexdigest()


def _tail_hash(path):
    """파일의 마지막 레코드 해시를 읽는다 (서버 재시작 후에도 체인 유지)."""
    if not path.exists():
        return GENESIS
    last = GENESIS
    with open(path, encoding="utf-8") as f:
        for line in f:
            if line.strip():
                last = json.loads(line).get("hash", GENESIS)
    return last


def write_audit(db, user, action, resource, detail, ip, result, rows=0):
    """감사 로그를 DB와 JSON Lines 파일에 동시에 기록한다.
    파일 로그는 레코드마다 이전 해시를 포함하는 해시 체인이라 사후 수정·삭제를 탐지할 수 있다.
    rows는 이번 요청으로 반환·내보낸 고객 건수로, 대량 조회 탐지에 쓰인다."""
    ts = datetime.now(timezone.utc).isoformat(timespec="milliseconds")
    body = {
        "ts": ts,
        "user_id": user["id"] if user else None,
        "username": user["username"] if user else None,
        "role": user["role"] if user else None,
        "action": action,
        "resource": resource,
        "detail": detail,
        "ip": ip,
        "result": result,
        "rows": rows,
    }
    db.execute(
        "INSERT INTO audit_logs(ts,user_id,username,role,action,resource,detail,ip,result,rows) VALUES(?,?,?,?,?,?,?,?,?,?)",
        (ts, body["user_id"], body["username"], body["role"], action, resource, detail, ip, result, rows),
    )
    path = config.AUDIT_LOG_PATH
    path.parent.mkdir(parents=True, exist_ok=True)
    with _lock:
        key = str(path)
        if key not in _last_hash:
            _last_hash[key] = _tail_hash(path)
        prev = _last_hash[key]
        h = _chain_hash(prev, body)
        with open(path, "a", encoding="utf-8") as f:
            f.write(json.dumps({**body, "prev": prev, "hash": h}, ensure_ascii=False) + "\n")
        _last_hash[key] = h
    for hook in _hooks:
        hook(db, {**body, "prev": prev, "hash": h})


def register_hook(fn):
    if fn not in _hooks:
        _hooks.append(fn)


def verify_chain(path=None):
    """해시 체인 검증. (정상 여부, 문제 줄 번호)를 반환한다."""
    path = path or config.AUDIT_LOG_PATH
    prev = GENESIS
    if not path.exists():
        return True, None
    with open(path, encoding="utf-8") as f:
        for n, line in enumerate(f, 1):
            if not line.strip():
                continue
            rec = json.loads(line)
            h, p = rec.pop("hash", None), rec.pop("prev", None)
            if p != prev or _chain_hash(prev, rec) != h:
                return False, n
            prev = h
    return True, None
