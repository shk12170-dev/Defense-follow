"""규칙 기반 탐지 엔진.

감사 로그 이벤트를 시간순으로 한 건씩 받아(feed) 규칙에 해당하면 경보를 돌려준다.
상태(사용자별 최근 접근 이력)를 유지하므로 배치 분석과 실시간 분석 모두 같은 코드를 쓴다.
"""
import json
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path

import yaml

RULES_PATH = Path(__file__).resolve().parent.parent / "rules" / "rules.yaml"
_KEEP = timedelta(minutes=120)  # 이력 보관 기간 (모든 규칙의 window/lookback보다 길게)


@dataclass
class Alert:
    ts: str
    rule_id: str
    rule_name: str
    severity: str
    mitre: str | None
    user_key: str
    username: str | None
    detail: dict = field(default_factory=dict)


def load_rules(path=None):
    with open(path or RULES_PATH, encoding="utf-8") as f:
        return yaml.safe_load(f)


def _parse(ts):
    return datetime.fromisoformat(ts)


def _user_key(ev):
    if ev.get("username"):
        return ev["username"]
    return f"ip:{ev.get('ip') or 'unknown'}"


class Detector:
    def __init__(self, cfg=None):
        self.cfg = cfg or load_rules()
        self.rules = self.cfg["rules"]
        self.data_actions = set(self.cfg["data_actions"])
        self.tz = timezone(timedelta(hours=self.cfg.get("utc_offset_hours", 9)))
        self.hist = {}        # user_key -> deque[(dt, rows, action)]
        self.last_fired = {}  # (rule_id, user_key) -> dt

    # ---- 내부 도구 ----
    def _cooling(self, rule, key, dt):
        last = self.last_fired.get((rule["id"], key))
        return last is not None and dt - last < timedelta(minutes=rule.get("cooldown_min", 0))

    def _fire(self, rule, key, dt, ev, detail):
        if self._cooling(rule, key, dt):
            return None
        self.last_fired[(rule["id"], key)] = dt
        return Alert(ev["ts"], rule["id"], rule["name"], rule["severity"], rule.get("mitre"),
                     key, ev.get("username"), detail)

    def _sum_rows(self, key, since, exclude_action=None):
        return sum(r for (t, r, a) in self.hist.get(key, ()) if t >= since and a != exclude_action)

    # ---- 이벤트 처리 ----
    def feed(self, ev):
        dt = _parse(ev["ts"])
        key = _user_key(ev)
        is_data = ev["action"] in self.data_actions and ev["result"] == "ok"

        # 라이브 이력은 현재 이벤트 반영 전에 R4(직전 조회량)를 계산해야 하므로 먼저 스냅샷 계산
        alerts = []
        for rule in self.rules:
            handler = getattr(self, f"_rule_{rule['type']}")
            a = handler(rule, ev, dt, key, is_data)
            if a:
                alerts.append(a)

        if is_data:
            q = self.hist.setdefault(key, deque())
            q.append((dt, ev.get("rows") or 0, ev["action"]))
            while q and dt - q[0][0] > _KEEP:
                q.popleft()
        return alerts

    def run(self, events):
        out = []
        for ev in sorted(events, key=lambda e: e["ts"]):
            out.extend(self.feed(ev))
        return out

    # ---- 규칙 구현 ----
    def _rule_volume(self, rule, ev, dt, key, is_data):
        if not is_data:
            return None
        since = dt - timedelta(minutes=rule["window_min"])
        total = self._sum_rows(key, since) + (ev.get("rows") or 0)
        if total >= rule["threshold_rows"]:
            return self._fire(rule, key, dt, ev, {
                "rows_in_window": total, "window_min": rule["window_min"],
                "threshold": rule["threshold_rows"], "last_action": ev["action"]})

    def _rule_off_hours(self, rule, ev, dt, key, is_data):
        if not is_data:
            return None
        hour = dt.astimezone(self.tz).hour
        if rule["start_hour"] <= hour < rule["end_hour"]:
            return self._fire(rule, key, dt, ev, {
                "local_hour": hour, "action": ev["action"], "resource": ev.get("resource")})

    def _rule_inactive_account(self, rule, ev, dt, key, is_data):
        if ev["action"] not in rule["actions"] or ev["result"] not in rule["results"]:
            return None
        detail = ev.get("detail") or ""
        if any(s in detail for s in rule["detail_contains"]):
            return self._fire(rule, key, dt, ev, {
                "action": ev["action"], "reason": detail, "ip": ev.get("ip")})

    def _rule_bulk_then_export(self, rule, ev, dt, key, is_data):
        if ev["action"] != rule["export_action"] or ev["result"] != "ok":
            return None
        since = dt - timedelta(minutes=rule["lookback_min"])
        prior = self._sum_rows(key, since, exclude_action=rule["export_action"])
        if prior >= rule["min_rows"]:
            return self._fire(rule, key, dt, ev, {
                "rows_before_export": prior, "lookback_min": rule["lookback_min"],
                "export_rows": ev.get("rows"), "resource": ev.get("resource")})


# ---- 입출력 ----
def load_events_from_file(path):
    events = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            if line.strip():
                ev = json.loads(line)
                ev.pop("prev", None)
                ev.pop("hash", None)
                events.append(ev)
    return events


def load_events_from_db(db):
    return [dict(r) for r in db.execute("SELECT * FROM audit_logs ORDER BY id")]


def save_alerts(db, alerts):
    """같은 (규칙, 사용자, 시각) 경보는 한 번만 저장한다. 새로 저장된 건수를 반환."""
    n = 0
    for a in alerts:
        cur = db.execute(
            "INSERT OR IGNORE INTO alerts(ts,rule_id,rule_name,severity,mitre,user_key,username,detail) VALUES(?,?,?,?,?,?,?,?)",
            (a.ts, a.rule_id, a.rule_name, a.severity, a.mitre, a.user_key, a.username,
             json.dumps(a.detail, ensure_ascii=False)))
        n += cur.rowcount
    db.commit()
    return n
