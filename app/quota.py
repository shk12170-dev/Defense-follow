"""서버 하드 쿼터: 일정 기간 동안 한 사용자에게 내줄 수 있는 고객정보 건수의 상한.

탐지(경보 후 대응)와 달리 데이터를 반환하기 전에 검사하므로, 어떤 속도로 천천히 읽어도
유출되는 최대 건수가 쿼터로 고정된다. 세 종류의 한도를 함께 적용하고 가장 빡빡한 것이 이긴다.
  1. windows : 모든 조회를 합친 기간별 한도 (24시간, 7일) - 하루 한도 미만으로 매일 조금씩 가져가는 다일 누적 제한
  2. limits  : 조회 유형별 한도 (상세·검색 / 목록 / 마스킹 해제)와 10분 같은 짧은 창 - 한꺼번에 많이 가져가는 것을 제한
  3. stepup_penalty : 재인증을 통과한 직후에는 모든 한도를 줄인다 (본인 인증 코드를 가진 내부자는 재인증만으로 한도를 되찾지 못하게)
남은 쿼터보다 많이 요청하면 남은 만큼만 내주고, 다 쓰면 거부(HTTP 429)한다. DEFENSE_MODE=off 이면 적용하지 않는다.
"""
import os
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


def profile_config(q, name=None):
    """쿼터 섹션 q에서 프로필 name(없으면 활성 프로필)의 windows·limits·stepup_penalty를 합쳐 돌려준다. profiles가 없으면 q 그대로."""
    profiles = q.get("profiles")
    if not profiles:
        return q
    name = name or os.environ.get("DEFENSE_QUOTA_PROFILE") or q.get("profile", "standard")
    prof = profiles.get(name) or {}
    return {"windows": prof.get("windows", q.get("windows", [])), "limits": prof.get("limits", []),
            "stepup_penalty": q.get("stepup_penalty")}


def _quota_cfg():
    """활성 프로필(환경변수 DEFENSE_QUOTA_PROFILE 또는 quota.profile)의 쿼터 설정."""
    return profile_config(_load().get("quota") or {})


def windows():
    """[{hours, rows:{role: 건수}}...] (활성 프로필 기준). 예전 형식(window_hours + rows)도 읽는다."""
    q = _quota_cfg()
    if "windows" in q:
        return q["windows"]
    if "rows" in q:
        return [{"hours": q.get("window_hours", 24), "rows": q["rows"]}]
    return []


def _label(minutes):
    return f"{minutes // 60}시간" if minutes % 60 == 0 and minutes >= 60 else f"{minutes}분"


def specs(role, action, cfg=None):
    """이 역할·동작에 적용되는 한도 목록 [(라벨, 분, 동작 집합 또는 None(전체), 상한)...]."""
    q = cfg if cfg is not None else _quota_cfg()
    out = []
    if "windows" in q:
        ws = q["windows"]
    elif "rows" in q:
        ws = [{"hours": q.get("window_hours", 24), "rows": q["rows"]}]
    else:
        ws = []
    for w in ws:
        if role in w["rows"]:
            m = int(w["hours"] * 60)
            out.append((_label(m), m, None, w["rows"][role]))
    for lim in q.get("limits") or []:
        if action in lim["actions"] and role in lim["rows"]:
            m = int(lim.get("minutes") or lim["hours"] * 60)
            out.append((f"{_label(m)}, {lim['name']}", m, frozenset(lim["actions"]), lim["rows"][role]))
    return out


def remaining(caps_used):
    """[(상한, 사용량, 라벨)...] 에서 가장 빡빡한 한도의 (남은 건수, 사용량, 상한, 라벨)을 돌려준다. 순수 함수."""
    best = None
    for cap, used, label in caps_used:
        rem = max(0, cap - used)
        if best is None or rem < best[0]:
            best = (rem, used, cap, label)
    return best


def evaluate(spec_list, used_fn, want, factor=1.0):
    """순수 함수: (내줄 수 있는 건수, 적용된 한도 정보). 서버와 측정 시뮬레이션이 같은 계산을 쓴다.
    used_fn(분, 동작 집합 또는 None) -> 그 기간에 이미 내준 건수, factor는 한도 축소 비율."""
    caps_used = [(int(cap * factor), used_fn(m, acts), label) for label, m, acts, cap in spec_list]
    best = remaining(caps_used)
    if best is None:
        return want, None
    rem, u, cap, label = best
    return min(want, rem), {"used": u, "cap": cap, "label": label}


def stepup_factor(db, user):
    """최근 재인증을 통과했다면 한도 축소 비율(예: 0.5), 아니면 1.0."""
    pen = _quota_cfg().get("stepup_penalty")
    if not pen:
        return 1.0
    since = (datetime.now(timezone.utc) - timedelta(hours=pen["hours"])).isoformat(timespec="milliseconds")
    row = db.execute("SELECT 1 FROM audit_logs WHERE user_id=? AND action='auth.stepup' AND result='ok' AND ts>=? LIMIT 1",
                     (user["id"], since)).fetchone()
    return pen["factor"] if row else 1.0


def _db_used(db, user, spec_list):
    """모든 한도의 사용량을 쿼리 한 번으로 구한다(요청마다 여러 번 합산하면 응답이 느려진다). used_fn 형태로 돌려준다."""
    all_actions = list(_load()["data_actions"])
    now = datetime.now(timezone.utc)
    cols, args = [], []
    for _label_, minutes, acts, _cap in spec_list:
        a = list(acts) if acts else all_actions
        since = (now - timedelta(minutes=minutes)).isoformat(timespec="milliseconds")
        cols.append(f"COALESCE(SUM(CASE WHEN ts>=? AND action IN ({','.join('?' * len(a))}) THEN rows ELSE 0 END),0)")
        args += [since, *a]
    widest = (now - timedelta(minutes=max(m for _l, m, _a, _c in spec_list))).isoformat(timespec="milliseconds")
    row = db.execute(f"SELECT {', '.join(cols)} FROM audit_logs WHERE user_id=? AND result='ok' AND ts>=?",
                     (*args, user["id"], widest)).fetchone()
    lookup = {(m, acts): row[i] for i, (_l, m, acts, _c) in enumerate(spec_list)}
    return lambda minutes, actions: lookup[(minutes, actions)]


def check(db, user, want, action="customer.list"):
    """(내줄 수 있는 건수, 적용된 한도 정보). 한도가 없거나 방어가 꺼져 있으면 (want, None)."""
    if not config.defense_enabled():
        return want, None
    sp = specs(user["role"], action)
    if not sp:
        return want, None
    return evaluate(sp, _db_used(db, user, sp), want, stepup_factor(db, user))


def enforce(db, user, request_ip, action, resource, want):
    """내줄 수 있는 건수를 반환한다. 0이면 blocked 기록을 남기고 429를 발생시킨다."""
    n, info = check(db, user, want, action)
    if n <= 0 and want > 0 and info is not None:
        write_audit(db, user, action, resource,
                    f"quota exceeded: {info['used']}/{info['cap']}건 ({info['label']})", request_ip, "blocked")
        db.commit()
        raise HTTPException(429, f"조회 한도({info['cap']}건/{info['label']})를 모두 사용했습니다. 보안 담당자에게 문의하세요")
    return n
