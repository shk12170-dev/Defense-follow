"""대시보드용 집계. 한 번의 호출로 화면에 필요한 모든 데이터를 만든다."""
import json
from datetime import datetime, timedelta, timezone

from app.detection import load_rules

KST = timezone(timedelta(hours=9))
BUCKET_MIN = 5


def build_stats(db, window_min=60):
    cfg = load_rules()
    data_actions = tuple(cfg["data_actions"])
    now = datetime.now(timezone.utc)
    since = now - timedelta(minutes=window_min)
    ph = ",".join("?" * len(data_actions))

    rows = db.execute(
        f"SELECT ts, username, rows FROM audit_logs WHERE result='ok' AND ts>=? AND action IN ({ph})",
        (since.isoformat(), *data_actions),
    ).fetchall()

    n_buckets = window_min // BUCKET_MIN
    start = now - timedelta(minutes=BUCKET_MIN * n_buckets)
    buckets = [0] * n_buckets
    per_user = {}
    for r in rows:
        t = datetime.fromisoformat(r["ts"])
        idx = int((t - start).total_seconds() // (BUCKET_MIN * 60))
        if 0 <= idx < n_buckets:
            buckets[idx] += r["rows"]
        per_user[r["username"]] = per_user.get(r["username"], 0) + r["rows"]

    labels = [(start + timedelta(minutes=BUCKET_MIN * i)).astimezone(KST).strftime("%H:%M") for i in range(n_buckets)]
    top_users = sorted(({"username": u, "rows": n} for u, n in per_user.items()), key=lambda x: -x["rows"])[:8]

    by_rule = [dict(r) for r in db.execute(
        "SELECT rule_id, rule_name, severity, COUNT(*) AS count FROM alerts GROUP BY rule_id ORDER BY rule_id")]

    recent_alerts = []
    for r in db.execute("SELECT * FROM alerts ORDER BY id DESC LIMIT 20"):
        d = dict(r)
        d["detail"] = json.loads(d["detail"])
        recent_alerts.append(d)

    locked = [dict(r) for r in db.execute(
        "SELECT username, role FROM users WHERE status='locked' ORDER BY username")]

    stepup = [dict(r) for r in db.execute(
        "SELECT username, role FROM users WHERE stepup_required=1 AND status='active' ORDER BY username")]

    events = [dict(r) for r in db.execute(
        "SELECT ts, username, action, resource, detail, result FROM audit_logs "
        "WHERE action IN ('response.lock','response.warn','response.stepup','auth.stepup','admin.unlock') OR result='blocked' "
        "OR (action='auth.login' AND result!='ok') "
        "ORDER BY id DESC LIMIT 15")]

    totals = {
        "alerts": db.execute("SELECT COUNT(*) FROM alerts").fetchone()[0],
        "alerts_high": db.execute("SELECT COUNT(*) FROM alerts WHERE severity IN ('high','critical')").fetchone()[0],
        "locked": len(locked),
        "stepup": len(stepup),
        "rows_window": sum(buckets),
    }
    return {
        "generated_at": now.isoformat(timespec="seconds"),
        "window_min": window_min,
        "bucket_min": BUCKET_MIN,
        "totals": totals,
        "buckets": [{"t": l, "rows": n} for l, n in zip(labels, buckets)],
        "top_users": top_users,
        "by_rule": by_rule,
        "recent_alerts": recent_alerts,
        "locked_users": locked,
        "stepup_users": stepup,
        "recent_events": events,
        "threshold": next((r["threshold_rows"] for r in cfg["rules"] if r["id"] == "R1"), None),
    }
