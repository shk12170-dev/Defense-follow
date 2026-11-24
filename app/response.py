"""실시간 탐지와 자동 대응.

감사 로그가 기록될 때마다 탐지 엔진에 전달하고, 심각도가 높은 경보가 나오면
경보를 저장한 뒤 해당 계정을 즉시 잠근다. 잠금은 다음 요청부터 적용된다
(토큰이 유효해도 매 요청마다 계정 상태를 DB에서 다시 확인하기 때문).
"""
import threading

from app import config
from app.audit import register_hook, write_audit
from app.detection import Detector, save_alerts

_lock = threading.Lock()
_detector = None


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
        if a.severity not in config.LOCK_SEVERITIES or not a.username:
            continue
        user = db.execute("SELECT * FROM users WHERE username=?", (a.username,)).fetchone()
        if user is None or user["status"] != "active":
            continue
        db.execute("UPDATE users SET status='locked' WHERE id=?", (user["id"],))
        write_audit(db, user, "response.lock", f"user/{a.username}",
                    f"rule={a.rule_id} {a.rule_name}", ev.get("ip"), "ok")
        db.commit()


register_hook(_on_event)
