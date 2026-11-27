"""쿼터 설정을 바꿨을 때 정상 업무 오탐과 공격 유출이 어떻게 달라지는지 합성 데이터로 측정한다.

서버와 같은 계산(app.quota.evaluate)을 메모리 위에서 돌려, 서버를 띄우지 않고도 설정 여러 개를 비교할 수 있다.
  - 정상 업무: scripts/benchmark.py 의 합성 30일 로그(상담원 5명·관리자 1명)를 시간순으로 재생해, 한도에 걸린 요청이 있는 날을 센다.
  - 공격: 한도에 걸릴 때까지 가능한 한 많이 가져가는 공격자의 유출 건수.
사용: python scripts/quota_study.py
"""
import sys
from collections import defaultdict
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from app import quota  # noqa: E402
from app.detection import load_rules  # noqa: E402

DATA_ACTIONS = load_rules()["data_actions"]
BROWSE = ["customer.view", "customer.search"]
LIST = ["customer.list"]


def make_cfg(browse10=None, browse_day=None, list10=None, list_day=None, unmask_day=None,
             total_day=(1500, 2000), total_week=(7000, 8000), penalty=None):
    """(상담원, 관리자) 값을 받아 쿼터 설정을 만든다. None이면 그 한도는 두지 않는다."""
    cfg = {"windows": [{"hours": 24, "rows": {"agent": total_day[0], "admin": total_day[1]}},
                       {"hours": 168, "rows": {"agent": total_week[0], "admin": total_week[1]}}], "limits": []}

    def add(name, actions, minutes, caps):
        if caps is not None:
            cfg["limits"].append({"name": name, "actions": actions, "minutes": minutes,
                                  "rows": {"agent": caps[0], "admin": caps[1]}})

    add("상세·검색", BROWSE, 10, browse10)
    add("상세·검색", BROWSE, 1440, browse_day)
    add("목록", LIST, 10, list10)
    add("목록", LIST, 1440, list_day)
    if unmask_day is not None:
        cfg["limits"].append({"name": "마스킹 해제", "actions": ["customer.unmask"], "minutes": 1440,
                              "rows": {"admin": unmask_day}})
    if penalty:
        cfg["stepup_penalty"] = {"hours": 24, "factor": penalty}
    return cfg


class History:
    def __init__(self):
        self.items = defaultdict(list)  # user -> [(분, 동작, 건수)]

    def used_fn(self, user, now_min):
        def used(minutes, actions):
            acts = set(actions) if actions else set(DATA_ACTIONS)
            lo = now_min - minutes
            return sum(r for (t, a, r) in self.items[user] if t > lo and a in acts)
        return used

    def add(self, user, t, action, rows):
        if rows > 0:
            self.items[user].append((t, action, rows))


def serve(hist, cfg, user, role, now_min, action, want, factor=1.0):
    n, _info = quota.evaluate(quota.specs(role, action, cfg), hist.used_fn(user, now_min), want, factor)
    hist.add(user, now_min, action, n)
    return n


# ---------------- 정상 업무 재생 ----------------
def normal_impact(cfg, events):
    hist = History()
    blocked_days = defaultdict(set)   # role -> {(user, 날짜)}
    denied_rows = total_rows = 0
    week_max = 0
    daily = defaultdict(int)
    t0 = None
    for e in sorted(events, key=lambda x: x["ts"]):
        if e["action"] not in DATA_ACTIONS:
            continue
        t = datetime.fromisoformat(e["ts"])
        t0 = t0 or t
        now_min = (t - t0).total_seconds() / 60
        role = "admin" if e["username"].startswith("admin") else "agent"
        got = serve(hist, cfg, e["username"], role, now_min, e["action"], e["rows"])
        total_rows += e["rows"]
        if got < e["rows"]:
            denied_rows += e["rows"] - got
            blocked_days[role].add((e["username"], e["ts"][:10]))
        daily[(e["username"], int(now_min // 1440))] += got
    for u in {k[0] for k in daily}:
        days = sorted(d for (uu, d) in daily if uu == u)
        for d in days:
            week_max = max(week_max, sum(daily.get((u, x), 0) for x in range(d - 6, d + 1)))
    agent_days = len({(e["username"], e["ts"][:10]) for e in events if e["username"].startswith("agent")})
    return {"agent_days": agent_days, "agent_blocked_days": len(blocked_days["agent"]),
            "admin_blocked_days": len(blocked_days["admin"]),
            "denied_pct": denied_rows / total_rows * 100, "week_max": week_max}


# ---------------- 공격자가 가져가는 최대량 ----------------
def burst_leak(cfg, role, action, per_request=50, factor=1.0):
    """한 유형만 쉬지 않고 요청(요청당 50건)할 때 한도에 걸릴 때까지 가져가는 건수."""
    hist, got, t = History(), 0, 0.0
    for _ in range(200):
        n = serve(hist, cfg, "x", role, t, action, per_request, factor)
        if n <= 0:
            break
        got += n
        t += 1 / 60  # 1초 간격
    return got


def best_effort_leak(cfg, role, minutes, per_request=50, step_min=1.0, factor=1.0, hist=None, t0=0.0):
    """모든 유형을 번갈아 시도하며 minutes 동안 가져갈 수 있는 최대 건수(공격자가 한도 사이를 오가는 경우)."""
    hist = hist or History()
    got, t = 0, t0
    end = t0 + minutes
    while t < end:
        for action in ("customer.search", "customer.list", "customer.unmask"):
            if action == "customer.unmask" and role != "admin":
                continue
            got += serve(hist, cfg, "x", role, t, action, per_request, factor)
        t += step_min
    return got


def multiday_leak(cfg, role, per_day, days=14, per_request=50, factor=1.0):
    """하루 per_day건을 목표로 매일 꾸준히 가져가는 공격자의 days일 누적 유출."""
    hist, total = History(), 0
    for d in range(days):
        got, t = 0, d * 1440 + 600
        while got < per_day:
            n = 0
            for action in ("customer.search", "customer.list"):
                n = serve(hist, cfg, "x", role, t, action, min(per_request, per_day - got), factor)
                got += n
                if n > 0:
                    break
            if n <= 0:
                break
            t += 3
        total += got
    return total


def no_list_events(events):
    """목록 열람을 하지 않는 업무(상세·검색만): 목록 조회 이벤트를 제거한다. 목록으로 하던 일을 검색·상세로 대신하는 양은
    이미 로그에 있는 검색·상세 이벤트에 들어 있다고 본다(가정). 이 가정이 틀리면 엄격 프로필도 오탐이 늘 수 있다."""
    return [e for e in events if e["action"] != "customer.list"]


def study(configs, events):
    """configs: {이름: 쿼터 설정} 또는 {이름: (쿼터 설정, 그 설정으로 재생할 업무 로그)}"""
    rows = []
    for name, val in configs.items():
        cfg, evs = val if isinstance(val, tuple) else (val, events)
        n = normal_impact(cfg, evs)
        rows.append({
            "name": name, "normal": n,
            "s1_agent_list": burst_leak(cfg, "agent", "customer.list"),
            "s4_admin_list": burst_leak(cfg, "admin", "customer.list", per_request=50),
            "day_agent": best_effort_leak(cfg, "agent", 1440),
            "day_agent_after_stepup": best_effort_leak(cfg, "agent", 1440, factor=(cfg.get("stepup_penalty") or {}).get("factor", 1.0)),
            "d14_1450": multiday_leak(cfg, "agent", 1450),
        })
    return rows


if __name__ == "__main__":
    import benchmark
    ev = benchmark.normal_events()
    configs = {
        "현재(쿼터: 24시간·7일만)": make_cfg(),
        "A 유형별 일일만": make_cfg(browse_day=(500, 500), list_day=(300, 300), unmask_day=20),
        "B +10분 쿼터(상세·검색 100, 목록 100)": make_cfg(browse10=(100, 100), browse_day=(500, 500), list10=(100, 100), list_day=(300, 300), unmask_day=20),
        "C B + 합계 하향(일 800)": make_cfg(browse10=(100, 100), browse_day=(500, 500), list10=(100, 100), list_day=(300, 300), unmask_day=20,
                                          total_day=(800, 2000), total_week=(3500, 8000)),
        "D C + 재인증 후 50%": make_cfg(browse10=(100, 100), browse_day=(500, 500), list10=(100, 100), list_day=(300, 300), unmask_day=20,
                                       total_day=(800, 2000), total_week=(3500, 8000), penalty=0.5),
        "E 목록 완화(10분 200, 일 600)": make_cfg(browse10=(100, 100), browse_day=(500, 500), list10=(200, 200), list_day=(600, 600), unmask_day=20,
                                              total_day=(1100, 2000), total_week=(5000, 8000), penalty=0.5),
    }
    for r in study(configs, ev):
        n = r["normal"]
        print(f"{r['name']}\n   정상 상담원 {n['agent_blocked_days']}/{n['agent_days']}일 걸림, 관리자 {n['admin_blocked_days']}일, 거부 {n['denied_pct']:.1f}%, 7일 최대 {n['week_max']}"
              f"\n   S1(상담원 목록) {r['s1_agent_list']} · S4(관리자 목록) {r['s4_admin_list']} · 하루 최대 {r['day_agent']} (재인증 후 {r['day_agent_after_stepup']}) · 14일×1,450 {r['d14_1450']}")
