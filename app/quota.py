"""서버 하드 쿼터: 일정 기간 동안 한 사용자에게 내줄 수 있는 고객정보 건수의 상한.

탐지(경보 후 대응)와 달리 데이터를 반환하기 전에 검사하므로, 어떤 속도로 천천히 읽어도
유출되는 최대 건수가 쿼터로 고정된다. 여러 기간(24시간, 7일)을 함께 적용해 하루 한도 미만으로
매일 조금씩 가져가는 다일 누적도 제한한다. 남은 쿼터보다 많이 요청하면 가장 빡빡한 창의 남은 만큼만
내주고, 다 쓰면 거부(HTTP 429)한다. DEFENSE_MODE=off 이면 적용하지 않는다.
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


def rules():
    """로드한 규칙 설정 전체 (다른 모듈이 같은 캐시를 쓰도록 공개)."""
    return _load()


def windows():
    """[{hours, rows:{role: 건수}}...]. 예전 형식(window_hours + rows)도 읽는다."""
    q = _load().get("quota") or {}
    if "windows" in q:
        return q["windows"]
    if "rows" in q:
        return [{"hours": q.get("window_hours", 24), "rows": q["rows"]}]
    return []


def remaining(caps_used):
    """[(상한, 사용량, 시간창)...] 에서 가장 빡빡한 창의 (남은 건수, 사용량, 상한, 시간창)을 돌려준다. 순수 함수."""
    best = None
    for cap, used, hours in caps_used:
        rem = max(0, cap - used)
        if best is None or rem < best[0]:
            best = (rem, used, cap, hours)
    return best


def used(db, user, hours):
    """최근 hours시간 동안 이 사용자에게 내준 고객정보 건수 (감사 로그의 성공 조회 합계)."""
    actions = _load()["data_actions"]
    since = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat(timespec="milliseconds")
    ph = ",".join("?" * len(actions))
    return db.execute(
        f"SELECT COALESCE(SUM(rows),0) FROM audit_logs WHERE user_id=? AND result='ok' AND ts>=? AND action IN ({ph})",
        (user["id"], since, *actions)).fetchone()[0]


def check(db, user, want):
    """(내줄 수 있는 건수, 적용된 창 정보). 한도가 없거나 방어가 꺼져 있으면 (want, None)."""
    if not config.defense_enabled():
        return want, None
    caps_used = [(w["rows"][user["role"]], used(db, user, w["hours"]), w["hours"])
                 for w in windows() if user["role"] in w["rows"]]
    best = remaining(caps_used)
    if best is None:
        return want, None
    rem, u, cap, hours = best
    return min(want, rem), {"used": u, "cap": cap, "hours": hours}


def enforce(db, user, request_ip, action, resource, want):
    """내줄 수 있는 건수를 반환한다. 0이면 blocked 기록을 남기고 429를 발생시킨다."""
    n, info = check(db, user, want)
    if n <= 0 and want > 0 and info is not None:
        write_audit(db, user, action, resource,
                    f"quota exceeded: {info['used']}/{info['cap']}건 ({info['hours']}시간)", request_ip, "blocked")
        db.commit()
        raise HTTPException(429, f"조회 한도({info['cap']}건/{info['hours']}시간)를 모두 사용했습니다. 보안 담당자에게 문의하세요")
    return n
