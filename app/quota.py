"""서버 하드 쿼터: 일정 기간 동안 한 사용자에게 내줄 수 있는 고객정보 건수의 상한.

탐지(경보 후 대응)와 달리 데이터를 반환하기 전에 검사하므로, 어떤 속도로 천천히 읽어도
유출되는 최대 건수가 쿼터로 고정된다. 남은 쿼터보다 많이 요청하면 남은 만큼만 내주고,
쿼터를 다 쓰면 거부(HTTP 429)한다. DEFENSE_MODE=off 이면 적용하지 않는다.
"""
from datetime import datetime, timedelta, timezone

from fastapi import HTTPException

from app import config
from app.audit import write_audit
from app.detection import load_rules

_rules = None


def _load():
    global _rules
    if _rules is None:
        _rules = load_rules()
    return _rules


def settings():
    return _load().get("quota") or {}


def used(db, user):
    """최근 window_hours 동안 이 사용자에게 내준 고객정보 건수 (감사 로그의 성공 조회 합계)."""
    cfg = settings()
    actions = _load()["data_actions"]
    since = (datetime.now(timezone.utc) - timedelta(hours=cfg.get("window_hours", 24))).isoformat(timespec="milliseconds")
    ph = ",".join("?" * len(actions))
    return db.execute(
        f"SELECT COALESCE(SUM(rows),0) FROM audit_logs WHERE user_id=? AND result='ok' AND ts>=? AND action IN ({ph})",
        (user["id"], since, *actions)).fetchone()[0]


def limit_for(user):
    return (settings().get("rows") or {}).get(user["role"])


def allowed(db, user, want):
    """이번 요청에서 내줄 수 있는 건수(<= want)와 (사용량, 한도)를 돌려준다. 한도가 없으면 want 그대로."""
    if not config.defense_enabled():
        return want, None, None
    cap = limit_for(user)
    if cap is None:
        return want, None, None
    u = used(db, user)
    return max(0, min(want, cap - u)), u, cap


def enforce(db, user, request_ip, action, resource, want):
    """내줄 수 있는 건수를 반환한다. 0이면 blocked 기록을 남기고 429를 발생시킨다."""
    n, u, cap = allowed(db, user, want)
    if n <= 0 and want > 0 and cap is not None:
        write_audit(db, user, action, resource,
                    f"quota exceeded: {u}/{cap}건 ({settings().get('window_hours', 24)}시간)", request_ip, "blocked")
        db.commit()
        raise HTTPException(429, f"조회 한도({cap}건/{settings().get('window_hours', 24)}시간)를 모두 사용했습니다. 보안 담당자에게 문의하세요")
    return n
