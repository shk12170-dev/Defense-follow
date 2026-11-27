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
_BASELINE_RESTORE_DAYS = 15  # R8 baseline_days(14일)보다 하루 길게


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
        days = _detector.daily.get(username)
        if days:  # 오늘(가장 최근 날짜) 누적만 지운다. 과거 기준선은 남겨 공격자가 기준선을 초기화하지 못하게 한다
            days.pop(max(days), None)
        for k in [k for k in _detector.last_fired if k[1] == username]:
            del _detector.last_fired[k]


def after_stepup(username):
    """재인증 통과 후: reset_on_stepup 규칙(R1)의 집계 창을 초기화한다.
    정상 사용자는 곧바로 다시 걸리지 않고, 재인증 후 다시 기준을 넘으면(24시간 안) 잠긴다."""
    with _lock:
        if _detector is None:
            return
        now = datetime.now(timezone.utc)
        for rule in _cfg()["rules"]:
            if rule.get("response") == "stepup" and rule.get("reset_on_stepup"):
                _detector.reset_window(rule["id"], username, now)


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


def _restored_detector(db, current):
    """서버 재시작 후 첫 이벤트에서 DB의 과거 조회 기록으로 탐지 상태(최근 이력·개인 기준선)를 복원한다.
    현재 이벤트는 이어서 feed로 처리하므로 제외한다."""
    det = Detector()
    since = (datetime.now(timezone.utc) - timedelta(days=_BASELINE_RESTORE_DAYS)).isoformat(timespec="milliseconds")
    actions = list(det.data_actions)
    ph = ",".join("?" * len(actions))
    rows = db.execute(
        f"SELECT ts, username, action, result, rows, ip FROM audit_logs WHERE ts>=? AND ts<? AND result='ok' AND action IN ({ph})",
        (since, current["ts"], *actions)).fetchall()
    det.warm([dict(r) for r in rows])
    return det


def _should_lock(alert):
    if alert.lock is not None:
        return alert.lock
    return alert.severity in config.LOCK_SEVERITIES


def _decide(db, alert, user):
    """경보에 대한 대응 단계를 정한다: 'lock' | 'stepup' | 'warn'.
    규칙이 response: stepup 이면 먼저 재인증을 요구하고, 같은 규칙이 escalate_min 이내에 다시 발동하면 잠금으로 올린다."""
    if alert.response == "stepup":
        rule = next((r for r in _cfg()["rules"] if r["id"] == alert.rule_id), {})
        since = (datetime.now(timezone.utc) - timedelta(minutes=rule.get("escalate_min", 1440))).isoformat(timespec="milliseconds")
        prior = db.execute(
            "SELECT COUNT(*) FROM audit_logs WHERE user_id=? AND action='response.stepup' AND ts>=? AND detail LIKE ?",
            (user["id"], since, f"rule={alert.rule_id} %")).fetchone()[0]
        if rule.get("escalate", True) is False:
            return "stepup"  # 반복해도 잠그지 않는 규칙(R5·R8): 더 높은 단계 규칙(R6)이 잠금을 담당
        return "lock" if prior else "stepup"
    return "lock" if _should_lock(alert) else "warn"


def _on_event(db, ev):
    global _detector
    if not config.defense_enabled():
        return
    with _lock:
        if _detector is None:
            _detector = _restored_detector(db, ev)
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
        action = _decide(db, a, user)
        if action == "lock":
            db.execute("UPDATE users SET status='locked' WHERE id=?", (user["id"],))
            write_audit(db, user, "response.lock", f"user/{a.username}",
                        f"rule={a.rule_id} {a.rule_name}", ev.get("ip"), "ok")
        elif action == "stepup":
            rule = next((r for r in _cfg()["rules"] if r["id"] == a.rule_id), {})
            # stepup_scope가 있는 규칙(R14)은 범위를 좁힌다. 이미 전체 재인증이 걸린 계정은 좁히지 않는다
            db.execute("UPDATE users SET stepup_scope = CASE WHEN stepup_required=1 AND stepup_scope IS NULL THEN NULL ELSE ? END, "
                       "stepup_required=1 WHERE id=?", (rule.get("stepup_scope"), user["id"]))
            write_audit(db, user, "response.stepup", f"user/{a.username}",
                        f"rule={a.rule_id} {a.rule_name}", ev.get("ip"), "ok")
        else:
            write_audit(db, user, "response.warn", f"user/{a.username}",
                        f"rule={a.rule_id} {a.rule_name}", ev.get("ip"), "ok")
        db.commit()


register_hook(_on_event)
