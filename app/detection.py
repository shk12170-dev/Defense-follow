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
_KEEP = timedelta(hours=25)  # 이력 보관 기간 (하루 누적 규칙의 window보다 길게)


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
    # None이면 심각도로 판단(high 이상 잠금), True/False면 규칙에서 명시한 대로 (예: 차단만 하고 잠그지 않음)
    lock: bool | None = None
    # 규칙에 명시된 대응: "stepup"(재인증 요구)·"lock"·"warn". None이면 lock 값과 심각도로 판단
    response: str | None = None


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
        self.fail_ips = {}    # username -> deque[(dt, ip)]: 로그인 실패 이력 (R13용)
        self.denied = {}      # user_key -> deque[dt]: 접근 거부(범위 밖 조회 시도) 이력 (R11용)
        self.floor = {}       # (rule_id, user_key) -> dt: 재인증 이후부터 다시 세는 기준 시각 (volume 규칙의 창 초기화)
        self.daily = {}       # user_key -> {현지 날짜: 조회 건수} (R8 기준선용, 오래된 날은 정리)

    # ---- 내부 도구 ----
    def _cooling(self, rule, key, dt):
        last = self.last_fired.get((rule["id"], key))
        return last is not None and dt - last < timedelta(minutes=rule.get("cooldown_min", 0))

    def _fire(self, rule, key, dt, ev, detail):
        if self._cooling(rule, key, dt):
            return None
        self.last_fired[(rule["id"], key)] = dt
        return Alert(ev["ts"], rule["id"], rule["name"], rule["severity"], rule.get("mitre"),
                     key, ev.get("username"), detail, rule.get("lock"), rule.get("response"))

    def _sum_rows(self, key, since, exclude_action=None):
        return sum(r for (t, r, a) in self.hist.get(key, ()) if t >= since and a != exclude_action)

    def reset_window(self, rule_id, key, dt):
        """재인증을 통과한 사용자의 해당 규칙 창을 초기화한다: 이후 조회부터 새로 세고, 쿨다운도 해제한다."""
        self.floor[(rule_id, key)] = dt
        self.last_fired.pop((rule_id, key), None)

    # ---- 이벤트 처리 ----
    def _remember(self, key, dt, ev):
        day = dt.astimezone(self.tz).date()
        d = self.daily.setdefault(key, {})
        d[day] = d.get(day, 0) + (ev.get("rows") or 0)
        for old in [k for k in d if (day - k).days > 60]:
            del d[old]
        q = self.hist.setdefault(key, deque())
        q.append((dt, ev.get("rows") or 0, ev["action"]))
        while q and dt - q[0][0] > _KEEP:
            q.popleft()

    def warm(self, events):
        """경보 없이 과거 이벤트로 상태(최근 이력, 개인 기준선)만 채운다. 서버 재시작 후 복원에 쓴다."""
        for ev in sorted(events, key=lambda e: e["ts"]):
            if ev["action"] in self.data_actions and ev["result"] == "ok":
                self._remember(_user_key(ev), _parse(ev["ts"]), ev)

    def feed(self, ev):
        dt = _parse(ev["ts"])
        key = _user_key(ev)
        is_data = ev["action"] in self.data_actions and ev["result"] == "ok"

        if ev["action"] == "auth.login" and ev["result"] == "failed" and ev.get("username"):
            fq = self.fail_ips.setdefault(ev["username"], deque())
            fq.append((dt, ev.get("ip")))
            while fq and dt - fq[0][0] > _KEEP:
                fq.popleft()

        if ev["result"] == "denied" and "not assigned" in (ev.get("detail") or ""):
            dq = self.denied.setdefault(key, deque())
            dq.append(dt)
            while dq and dt - dq[0] > _KEEP:
                dq.popleft()

        # 라이브 이력은 현재 이벤트 반영 전에 R4(직전 조회량)를 계산해야 하므로 먼저 스냅샷 계산
        alerts = []
        for rule in self.rules:
            handler = getattr(self, f"_rule_{rule['type']}")
            a = handler(rule, ev, dt, key, is_data)
            if a:
                alerts.append(a)

        if is_data:
            self._remember(key, dt, ev)
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
        since = max(since, self.floor.get((rule["id"], key), since))
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

    def _rule_event_match(self, rule, ev, dt, key, is_data):
        """동작·결과·상세 문구가 모두 맞는 이벤트 하나로 판단하는 단순 매칭 규칙."""
        if ev["action"] not in rule["actions"] or ev["result"] not in rule["results"]:
            return None
        detail = ev.get("detail") or ""
        if any(s in detail for s in rule["detail_contains"]):
            return self._fire(rule, key, dt, ev, {
                "action": ev["action"], "reason": detail, "ip": ev.get("ip")})

    _rule_inactive_account = _rule_event_match  # R3의 기존 type 이름 호환

    def _rule_baseline(self, rule, ev, dt, key, is_data):
        """사용자별 기준선(UEBA): 오늘 누적 조회량이 본인의 과거 평균보다 크게 높으면 경고.
        고정 임계값(R5)보다 낮은 '그 사람에게는 이례적인' 증가를 잡는다. 기준선 일수가 부족하면 판단하지 않는다."""
        if not is_data:
            return None
        today = dt.astimezone(self.tz).date()
        d = self.daily.get(key, {})
        past = [r for day, r in d.items() if 0 < (today - day).days <= rule["baseline_days"]]
        if len(past) < rule["min_days"]:
            return None
        avg = sum(past) / len(past)
        total = d.get(today, 0) + (ev.get("rows") or 0)
        limit = max(rule["min_rows"], rule["multiplier"] * avg)
        if total >= limit:
            return self._fire(rule, key, dt, ev, {
                "rows_today": total, "baseline_avg": round(avg, 1), "baseline_days": len(past),
                "multiplier": rule["multiplier"], "threshold": round(limit)})

    def _rule_denied_burst(self, rule, ev, dt, key, is_data):
        """범위 밖 고객 조회 거부가 짧은 시간에 반복: ID를 순차로 넣어 보며 탐색하는 행동(IDOR 스캔)."""
        if ev["result"] != "denied" or "not assigned" not in (ev.get("detail") or ""):
            return None
        since = dt - timedelta(minutes=rule["window_min"])
        n = sum(1 for t in self.denied.get(key, ()) if t >= since)
        if n >= rule["threshold_count"]:
            return self._fire(rule, key, dt, ev, {
                "denied_in_window": n, "window_min": rule["window_min"], "threshold": rule["threshold_count"],
                "last_resource": ev.get("resource")})

    def _rule_login_spray(self, rule, ev, dt, key, is_data):
        """한 계정에 대한 로그인 실패가 여러 서로 다른 IP에서 짧은 시간에 발생: 분산 비밀번호 대입(스프레이).
        IP마다 시도가 적어 (아이디, IP) 단위 스로틀을 피하므로, 계정 기준으로 서로 다른 IP 수를 센다."""
        if ev["action"] != "auth.login" or ev["result"] != "failed" or not ev.get("username"):
            return None
        since = dt - timedelta(minutes=rule["window_min"])
        ips = {ip for t, ip in self.fail_ips.get(ev["username"], ()) if t >= since and ip}
        if len(ips) >= rule["threshold_ips"]:
            return self._fire(rule, ev["username"], dt, ev, {
                "distinct_ips": len(ips), "window_min": rule["window_min"], "threshold": rule["threshold_ips"],
                "sample_ips": sorted(ips)[:5]})

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
    from app import config
    n = 0
    fresh = []
    for a in alerts:
        cur = db.execute(
            "INSERT OR IGNORE INTO alerts(ts,rule_id,rule_name,severity,mitre,user_key,username,detail) VALUES(?,?,?,?,?,?,?,?)",
            (a.ts, a.rule_id, a.rule_name, a.severity, a.mitre, a.user_key, a.username,
             json.dumps(a.detail, ensure_ascii=False)))
        n += cur.rowcount
        if cur.rowcount:
            fresh.append(a)
    db.commit()
    if fresh:  # ELK(Filebeat)가 수집할 수 있도록 새로 저장된 경보만 JSON Lines로도 남긴다
        config.ALERT_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
        with open(config.ALERT_LOG_PATH, "a", encoding="utf-8") as f:
            for a in fresh:
                f.write(json.dumps({"ts": a.ts, "rule_id": a.rule_id, "rule_name": a.rule_name,
                                    "severity": a.severity, "mitre": a.mitre, "user_key": a.user_key,
                                    "username": a.username, "detail": a.detail}, ensure_ascii=False) + "\n")
    return n
