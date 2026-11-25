"""실시간 탐지와 자동 대응.

감사 로그가 기록될 때마다 탐지 엔진에 전달하고, 경보에 따라 단계적으로 대응한다.
  - 경고(warn): 경보를 저장하고 대응 이벤트(response.warn)를 남긴다. 계정은 그대로 둔다.
  - 잠금(lock): high 이상 경보이면 계정을 즉시 잠근다. 규칙에 lock: false가 있으면 잠그지 않는다.
잠금은 다음 요청부터 적용된다 (토큰이 유효해도 매 요청마다 계정 상태를 DB에서 다시 확인하기 때문).
"""
import threading
from datetime import datetime, timedelta, timezone

from app import config
from app.audit import register_hook, write_audit
from app.detection import Detector, load_rules, save_alerts

_lock = threading.Lock()
_detector = None
_rules_cfg = None


def reset():
    global _detector
    with _lock:
        _detector = None


def forget(username):
    """사용자의 탐지 이력·쿨다운을 지운다 (잠금 해제 후 재감시용)."""
    with _lock:
        if _detector is None:
            return
        _detector.hist.pop(username, None)
        for k in [k for k in _detector.last_fired if k[1] == username]:
            del _detector.last_fired[k]


def _cfg():
    global _rules_cfg
    if _rules_cfg is None:
        _rules_cfg = load_rules()
    return _rules_cfg


def pre_export_check(db, user):
    """내보내기 직전 점검: 직전 조회량이 R4 기준 이상이면 사유를 담은 dict를, 아니면 None을 반환한다.
    경보가 나온 뒤에 막는 것이 아니라 반출 자체를 사전에 거부하기 위한 것이다."""
    if not config.defense_enabled():
        return None
    cfg = _cfg()
    r4 = next((r for r in cfg["rules"] if r["id"] == "R4"), None)
    if r4 is None:
        return None
    since = (datetime.now(timezone.utc) - timedelta(minutes=r4["lookback_min"])).isoformat(timespec="milliseconds")
    actions = [a for a in cfg["data_actions"] if a != r4["export_action"]]
    ph = ",".join("?" * len(actions))
    total = db.execute(
        f"SELECT COALESCE(SUM(rows),0) FROM audit_logs WHERE user_id=? AND result='ok' AND ts>=? AND action IN ({ph})",
        (user["id"], since, *actions)).fetchone()[0]
    if total >= r4["min_rows"]:
        return {"rows_before": total, "lookback_min": r4["lookback_min"], "min_rows": r4["min_rows"]}
    return None


def _should_lock(alert):
    if alert.lock is not None:
        return alert.lock
    return alert.severity in config.LOCK_SEVERITIES


def _on_event(db, ev):
    global _detector
    if not config.defense_enabled():
        return
    with _lock:
        if _detector is None:
            _detector = Detector()
        alerts = _detector.feed(ev)
    if not alerts:
        return
    save_alerts(db, alerts)
    for a in alerts:
        if not a.username:
            continue
        user = db.execute("SELECT * FROM users WHERE username=?", (a.username,)).fetchone()
        if user is None or user["status"] != "active":
            continue
        if _should_lock(a):
            db.execute("UPDATE users SET status='locked' WHERE id=?", (user["id"],))
            write_audit(db, user, "response.lock", f"user/{a.username}",
                        f"rule={a.rule_id} {a.rule_name}", ev.get("ip"), "ok")
        else:
            write_audit(db, user, "response.warn", f"user/{a.username}",
                        f"rule={a.rule_id} {a.rule_name}", ev.get("ip"), "ok")
        db.commit()


register_hook(_on_event)
