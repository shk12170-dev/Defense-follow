"""방어 OFF/ON 전후 비교 측정. 결과를 docs/benchmark.{json,md,html}로 저장한다.

사용: python scripts/benchmark.py [--customers 4000]

- 시나리오 비교: 같은 공격을 DEFENSE_MODE=off / on 에서 각각 실행해 피해 규모를 비교
- 오버헤드: 정상 요청의 응답 시간 차이
- 오탐: 합성 업무일 30일치 로그에 규칙을 적용
- 회피: 공격자가 속도를 늦추면 R1이 언제부터 놓치는지
RBAC·마스킹·조회 상한은 두 모드 모두 켜져 있다. 끄는 것은 실시간 탐지·자동 차단뿐이다.
"""
import argparse
import contextlib
import html
import importlib
import io
import json
import os
import random
import statistics
import sys
import tempfile
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

PW = "Demo#2026pw"
KST = timezone(timedelta(hours=9))


@contextlib.contextmanager
def make_app(mode, n_customers):
    from fastapi.testclient import TestClient
    with tempfile.TemporaryDirectory() as tmp:
        os.environ["DEFENSE_DB"] = str(Path(tmp) / "b.db")
        os.environ["DEFENSE_AUDIT_LOG"] = str(Path(tmp) / "audit.jsonl")
        os.environ["DEFENSE_ALERT_LOG"] = str(Path(tmp) / "alerts.jsonl")
        os.environ["DEFENSE_MODE"] = mode
        from app import config
        importlib.reload(config)
        from app import audit, response
        audit._last_hash.clear()
        response.reset()
        from scripts import seed
        importlib.reload(seed)
        with contextlib.redirect_stdout(io.StringIO()):
            seed.main(n_customers=n_customers)
        from app import main
        with TestClient(main.app) as c:
            yield c


def login(c, user):
    r = c.post("/auth/login", json={"username": user, "password": PW})
    return {"Authorization": f"Bearer {r.json()['access_token']}"} if r.status_code == 200 else None


def db_rows(sql, args=()):
    from app import db as dbm
    conn = dbm.connect()
    try:
        return [dict(r) for r in conn.execute(sql, args)]
    finally:
        conn.close()


def first_alert_delay_ms(rule_id, t_start, users=None):
    """t_start 이후, (지정한 계정의) 첫 경보까지 걸린 시간. 앞선 시나리오의 경보는 제외한다."""
    rows = [r for r in db_rows("SELECT ts, username FROM alerts WHERE rule_id=? ORDER BY id", (rule_id,))
            if datetime.fromisoformat(r["ts"]) >= t_start and (users is None or r["username"] in users)]
    if not rows:
        return None
    return round((datetime.fromisoformat(rows[0]["ts"]) - t_start).total_seconds() * 1000)


# ---------------- 1. 시나리오 비교 ----------------
def scenario_bulk(c):
    h = login(c, "agent01")
    t_start = datetime.now(timezone.utc)
    t0 = time.perf_counter()
    rows, blocked_at, block_ms = 0, None, None
    for p in range(1, 31):
        r = c.get(f"/customers?page={p}&size=50", headers=h)
        if r.status_code != 200:
            blocked_at, block_ms = p, round((time.perf_counter() - t0) * 1000)
            break
        rows += len(r.json()["items"])
    return {"rows": rows, "blocked": blocked_at is not None, "block_request": blocked_at,
            "block_ms": block_ms, "alert_delay_ms": first_alert_delay_ms("R1", t_start),
            "alerts": len(db_rows("SELECT 1 FROM alerts WHERE username='agent01'"))}


def scenario_dormant(c):
    t_start = datetime.now(timezone.utc)
    codes = []
    for u in ("retired01", "dormant01"):
        r = c.post("/auth/login", json={"username": u, "password": PW})
        codes.append(r.status_code)
    who = ("retired01", "dormant01")
    return {"login_denied": all(x == 403 for x in codes),
            "alert_delay_ms": first_alert_delay_ms("R3", t_start, who),
            "alerts": len(db_rows("SELECT 1 FROM alerts WHERE username IN ('retired01','dormant01')"))}


def scenario_exfil(c):
    h = login(c, "admin01")
    t_start = datetime.now(timezone.utc)
    rows = 0
    for p in range(1, 6):
        rows += len(c.get(f"/customers?page={p}&size=50", headers=h).json()["items"])
    exports, blocked = 0, False
    for _ in range(5):  # 공격자가 반복해서 내보내기를 시도
        r = c.get("/customers/export?limit=1000&reason=점검용 반출 시험", headers=h)
        if r.status_code == 200:
            exports += 1
            rows += r.json()["count"]
        else:
            blocked = True
            break
    status = db_rows("SELECT status FROM users WHERE username='admin01'")[0]["status"]
    delay = first_alert_delay_ms("R7", t_start)
    if delay is None:
        delay = first_alert_delay_ms("R4", t_start)
    return {"rows": rows, "exports_done": exports, "blocked": blocked, "final_status": status,
            "alert_delay_ms": delay,
            "alerts": len(db_rows("SELECT 1 FROM alerts WHERE rule_id IN ('R4','R7')"))}


def run_scenarios(mode, n_customers):
    with make_app(mode, n_customers) as c:
        return {"bulk": scenario_bulk(c), "dormant": scenario_dormant(c), "exfil": scenario_exfil(c)}


# ---------------- 2. 오버헤드 ----------------
def run_overhead(mode, n_customers, per_agent=120):
    with make_app(mode, n_customers) as c:
        agents = [f"agent0{i}" for i in range(1, 6)]
        heads = {a: login(c, a) for a in agents}
        ids = {a: [r["id"] for r in db_rows(
            "SELECT c.id FROM customers c JOIN users u ON u.id=c.assigned_agent_id WHERE u.username=? LIMIT ?",
            (a, per_agent))] for a in agents}
        for a in agents[:1]:  # 워밍업
            c.get(f"/customers/{ids[a][0]}", headers=heads[a])
        times = []
        for i in range(per_agent):
            for a in agents:
                t0 = time.perf_counter()
                r = c.get(f"/customers/{ids[a][i]}", headers=heads[a])
                times.append((time.perf_counter() - t0) * 1000)
                assert r.status_code == 200, "정상 요청이 차단되면 안 된다"
        times.sort()
        return {"requests": len(times), "mean_ms": round(statistics.mean(times), 2),
                "p95_ms": round(times[int(len(times) * 0.95)], 2)}


# ---------------- 3. 오탐 (합성 업무일) ----------------
def _detector(threshold):
    from app.detection import Detector, load_rules
    cfg = load_rules()
    for r in cfg["rules"]:
        if r["id"] == "R1":
            r["threshold_rows"] = threshold
    return Detector(cfg)


def run_false_positive(days=30, seed=7, threshold=300):
    rnd = random.Random(seed)
    events = []

    def ev(ts, user, action, rows, role="agent"):
        return {"ts": ts.astimezone(timezone.utc).isoformat(), "username": user, "action": action,
                "result": "ok", "rows": rows, "detail": None, "ip": "10.0.0.5", "resource": None}

    for d in range(days):
        day = datetime(2026, 9, 1, tzinfo=KST) + timedelta(days=d)
        for a in range(1, 6):
            t = day + timedelta(hours=9)
            while t < day + timedelta(hours=18):
                if not (timedelta(hours=12) <= t - day < timedelta(hours=13)):  # 점심시간 제외
                    kind = rnd.random()
                    if kind < 0.7:
                        events.append(ev(t, f"agent0{a}", "customer.view", 1))
                    elif kind < 0.95:
                        events.append(ev(t, f"agent0{a}", "customer.search", rnd.randint(1, 10)))
                    else:  # 가끔 목록을 여러 페이지 넘겨 봄 (바쁜 시간)
                        for k in range(rnd.randint(2, 5)):
                            events.append(ev(t + timedelta(seconds=20 * k), f"agent0{a}", "customer.list", 20))
                t += timedelta(minutes=rnd.uniform(1, 6))
        t = day + timedelta(hours=10)  # 관리자: 오전 조회 후 100건 내보내기
        events.append(ev(t, "admin01", "customer.view", 1))
        events.append(ev(t + timedelta(minutes=30), "admin01", "customer.export", 100))
    alerts = _detector(threshold).run(events)
    locks = [a for a in alerts if _is_lock(a)]
    return {"days": days, "events": len(events), "agent_days": days * 5, "alerts": len(alerts),
            "locks": len(locks), "warns": len(alerts) - len(locks),
            "by_rule": {r: sum(1 for a in alerts if a.rule_id == r) for r in ("R1", "R2", "R3", "R4", "R5", "R6", "R7", "R8")},
            "examples": [f"{a.rule_id} {a.user_key} {a.detail.get('rows_in_window')}건" for a in alerts[:3]]}


# ---------------- 4. 회피 (저속 공격) ----------------
def _is_lock(alert):
    """경보가 계정 잠금으로 이어지는지 (규칙의 lock 값이 없으면 심각도로 판단)."""
    if alert.lock is not None:
        return alert.lock
    return alert.severity in ("high", "critical")


def _agent_quota():
    from app.detection import load_rules
    return load_rules()["quota"]["rows"]["agent"]


QUOTA_AGENT = _agent_quota()


def run_evasion(threshold=300, rates=(3, 5, 10, 20, 30, 60, 150), hours=8):
    out = []
    start = datetime(2026, 11, 10, 14, 0, tzinfo=KST)
    for rate in rates:  # 분당 조회 건수
        step = 50 / rate  # 50건씩 가져오는 간격(분)
        events, t = [], start
        while t < start + timedelta(hours=hours):
            events.append({"ts": t.astimezone(timezone.utc).isoformat(), "username": "insider01",
                           "action": "customer.list", "result": "ok", "rows": 50, "detail": None,
                           "ip": "10.0.0.9", "resource": None})
            t += timedelta(minutes=step)
        alerts = _detector(threshold).run(events)
        total = len(events) * 50

        def at(alert):
            if alert is None:
                return None, None
            first = datetime.fromisoformat(alert.ts)
            n = sum(1 for e in events if datetime.fromisoformat(e["ts"]) <= first)
            return round((first - start.astimezone(timezone.utc)).total_seconds() / 60, 1), n * 50

        warn = next((a for a in alerts if not _is_lock(a)), None)
        lock = next((a for a in alerts if _is_lock(a)), None)
        (wm, wr), (lm, lr) = at(warn), at(lock)
        out.append({"rate": rate, "total_rows": total, "warn_rule": warn.rule_id if warn else None,
                    "warn_min": wm, "warn_rows": wr, "lock_rule": lock.rule_id if lock else None,
                    "lock_min": lm, "lock_rows": lr, "rows_leaked": lr if lock else total,
                    "quota_leaked": min(lr if lock else total, QUOTA_AGENT),
                    "detected": lock is not None})
    return out


# ---------------- 5. 임계값 트레이드오프 ----------------
def run_tradeoff(thresholds=(200, 300, 400, 500)):
    out = []
    for thr in thresholds:
        fp = run_false_positive(threshold=thr)
        leak = run_evasion(threshold=thr, rates=(60,))[0]
        out.append({"threshold": thr, "fp_locks": fp["locks"], "agent_days": fp["agent_days"],
                    "leak_at_60": leak["rows_leaked"], "detected": leak["detected"]})
    return out


# ---------------- 리포트 ----------------
def fmt(v, unit=""):
    if v is None:
        return "-"
    if isinstance(v, bool):
        return "예" if v else "아니오"
    if isinstance(v, int):
        return f"{v:,}{unit}"
    return f"{v}{unit}"


def build_sections(res):
    off, on = res["scenarios"]["off"], res["scenarios"]["on"]
    s1 = [
        ["확보한 고객 정보 건수", fmt(off["bulk"]["rows"], "건"), fmt(on["bulk"]["rows"], "건")],
        ["차단 여부", fmt(off["bulk"]["blocked"]), fmt(on["bulk"]["blocked"])],
        ["차단된 요청 번호", fmt(off["bulk"]["block_request"]), fmt(on["bulk"]["block_request"])],
        ["첫 경보까지 걸린 시간", fmt(off["bulk"]["alert_delay_ms"], "ms"), fmt(on["bulk"]["alert_delay_ms"], "ms")],
        ["발생한 경보 수", fmt(off["bulk"]["alerts"], "건"), fmt(on["bulk"]["alerts"], "건")],
    ]
    s3 = [
        ["로그인 거부 (접근통제)", fmt(off["dormant"]["login_denied"]), fmt(on["dormant"]["login_denied"])],
        ["경보 발생 수", fmt(off["dormant"]["alerts"], "건"), fmt(on["dormant"]["alerts"], "건")],
        ["첫 경보까지 걸린 시간", fmt(off["dormant"]["alert_delay_ms"], "ms"), fmt(on["dormant"]["alert_delay_ms"], "ms")],
    ]
    s4 = [
        ["반출된 고객 정보 건수 (조회 250 + 내보내기)", fmt(off["exfil"]["rows"], "건"), fmt(on["exfil"]["rows"], "건")],
        ["성공한 내보내기 횟수 (시도 5회)", fmt(off["exfil"]["exports_done"], "회"), fmt(on["exfil"]["exports_done"], "회")],
        ["내보내기 사전 차단", fmt(off["exfil"]["blocked"]), fmt(on["exfil"]["blocked"])],
        ["계정 최종 상태", off["exfil"]["final_status"], on["exfil"]["final_status"]],
        ["첫 경보까지 걸린 시간", fmt(off["exfil"]["alert_delay_ms"], "ms"), fmt(on["exfil"]["alert_delay_ms"], "ms")],
    ]
    ov = res["overhead"]
    overhead = [
        ["평균 응답 시간", fmt(ov["off"]["mean_ms"], "ms"), fmt(ov["on"]["mean_ms"], "ms")],
        ["p95 응답 시간", fmt(ov["off"]["p95_ms"], "ms"), fmt(ov["on"]["p95_ms"], "ms")],
        ["측정 요청 수", fmt(ov["off"]["requests"], "건"), fmt(ov["on"]["requests"], "건")],
    ]
    fp = res["false_positive"]
    rate = fp["locks"] / fp["agent_days"] * 100
    fp_rows = [[f"합성 업무일 {fp['days']}일 (이벤트 {fp['events']:,}건, 상담원 {fp['agent_days']}명·일)",
                f"계정 잠금 {fp['locks']}건 ({rate:.2f}%), 경고 {fp['warns']}건",
                ", ".join(f"{k}:{v}" for k, v in fp["by_rule"].items() if v) or "경보 없음"]]
    to_rows = [[f"{t['threshold']}건/10분", f"{t['fp_locks']}건 ({t['fp_locks'] / t['agent_days'] * 100:.2f}%)",
                fmt(t["leak_at_60"], "건") if t["detected"] else "차단 못함"] for t in res["tradeoff"]]

    def warn_txt(e):
        return f"{e['warn_rule']} · {e['warn_min']}분 후 ({e['warn_rows']:,}건)" if e["warn_rule"] else "없음"

    def lock_txt(e):
        return f"{e['lock_rule']} · {e['lock_min']}분 후" if e["lock_rule"] else "**차단 못함**"

    ev_rows = [[f"{e['rate']}건/분", warn_txt(e), lock_txt(e), fmt(e["rows_leaked"], "건"), fmt(e["quota_leaked"], "건")] for e in res["evasion"]]

    ev = {e["rate"]: e for e in res["evasion"]}
    # 1차 구현(2026-11-25 07:53 KST 측정)의 값. 같은 시나리오·같은 측정 방식의 이전 결과다.
    imp = [
        ["시나리오 4: 반출된 건수 (방어 ON)", "1,250건", fmt(on["exfil"]["rows"], "건")],
        ["시나리오 4: 성공한 내보내기", "1회 (1,000건 유출 후 계정 잠금)", fmt(on["exfil"]["exports_done"], "회")],
    ]
    for rate_ in (10, 20):
        if rate_ in ev:
            old = {10: "4,800건 (차단 못함)", 20: "9,600건 (차단 못함)"}[rate_]
            imp.append([f"분당 {rate_}건 저속 공격 8시간 유출", old,
                        f"{ev[rate_]['rows_leaked']:,}건 ({lock_txt(ev[rate_]).replace('**', '')})"])
    imp.append(["정상 업무 오탐으로 인한 계정 잠금", "1건 (0.67%)", f"{fp['locks']}건 ({rate:.2f}%), 경고 {fp['warns']}건"])
    return [
        ("시나리오 1: 상담원 대량 조회 (R1, 쿠팡형)", ["지표", "방어 OFF", "방어 ON"], s1),
        ("시나리오 3: 퇴사자·휴면 계정 접근 (R3)", ["지표", "방어 OFF", "방어 ON"], s3),
        ("시나리오 4: 대량 조회 후 외부 반출 (R4·R7, 롯데카드형)", ["지표", "방어 OFF", "방어 ON"], s4),
        ("성능 오버헤드 (정상 요청)", ["지표", "방어 OFF", "방어 ON"], overhead),
        ("2차 보완 전후 비교 (누적 조회량·단계적 대응·반출 사전 차단)", ["항목", "1차 구현", "2차 보완"], imp),
        ("오탐 평가 (R1 임계값 300건/10분)", ["대상", "결과", "규칙별"], fp_rows),
        ("임계값 조정: 오탐 대 유출 (R1)", ["R1 임계값", "정상 업무로 인한 잠금", "분당 60건 공격 시 유출"], to_rows),
        ("저속 공격 분석 (8시간 지속, R1·R5·R6 적용)", ["조회 속도", "1단계 경고", "2단계 차단(잠금)", "유출 건수(탐지만)", f"유출 상한(하드 쿼터 {QUOTA_AGENT:,}건 적용)"], ev_rows),
    ]


NOTES = [
    "RBAC·마스킹·조회 상한(페이지당 50건)은 두 모드 모두 켜져 있다. 비교 대상은 실시간 탐지, 자동 차단, 반출 사전 차단이다.",
    "조회에 대한 경보는 요청 처리 시점에 발생하고 잠금은 다음 요청부터 적용되므로, R1 임계값(300건)까지는 확보할 수 있다. 내보내기는 직전 조회량을 검사해 실행 전에 거부한다(사전 차단).",
    "R7(내보내기 사전 차단)은 반출만 막고 계정은 잠그지 않는다(보안 담당자 확인 요청). 조회를 직전 30분 200건 미만으로 나눠 읽은 뒤 내보내면 R7을 피할 수 있으며, 이는 일일 누적 규칙(R5·R6)이 보완한다.",
    "참고: 롯데카드 사고는 침해 인지까지 17일이 걸렸다는 보도가 있다(언론 보도 기준). 이 모의 시스템의 경보는 같은 요청 안에서 발생한다.",
    "오탐 평가는 무작위로 만든 합성 로그이며 실제 업무 패턴 검증이 아니다. 오탐으로 잠기면 정상 상담원이 업무를 못 하므로, 운영 적용 전에는 실제 로그로 임계값을 조정해야 한다. 경고 단계(R5)는 계정을 잠그지 않는다.",
    "임계값을 올리면 잠금 오탐은 줄지만 공격 시 유출되는 건수가 늘어난다. 둘 사이의 균형이 규칙 튜닝의 핵심이다.",
    "하드 쿼터(상담원 1,500건/24시간)는 속도와 관계없이 반환 전에 적용되므로 유출 상한이 쿼터로 고정된다. 위 표의 쿼터 열은 탐지 결과와 쿼터 상한 중 작은 값이며, 서버가 실제로 상한을 지키는지는 tests/test_day11_quota.py가 검증한다.",
    "저속 공격: 하루 누적 1,200건(경고)·2,000건(차단) 미만이면 여전히 탐지하지 못한다(분당 약 2.5건 이하로 8시간). 사용자별 기준선 규칙(R8)은 평소 조회량이 적은 사용자의 급증만 잡고, 평소 하루 800건 넘게 보는 상담원에는 효과가 없다(tests/test_day10_baseline.py).",
    "측정은 단일 PC의 인프로세스 테스트 클라이언트 기준이라 네트워크 지연은 포함하지 않는다. 시간 값은 실행마다 다소 달라진다.",
]


def to_markdown(res):
    out = ["# 방어 전후 비교 결과", "", f"측정 시각: {res['generated']} · 더미 고객 {res['customers']:,}건", ""]
    for title, head, rows in build_sections(res):
        out += [f"## {title}", "", "| " + " | ".join(head) + " |", "|" + "---|" * len(head)]
        out += ["| " + " | ".join(r) + " |" for r in rows] + [""]
    out += ["## 해석 시 유의사항", ""] + [f"- {n}" for n in NOTES] + [""]
    return "\n".join(out)


def to_html(res):
    e = html.escape
    parts = []
    for title, head, rows in build_sections(res):
        th = "".join(f"<th>{e(h)}</th>" for h in head)
        tr = "".join("<tr>" + "".join(f"<td>{e(c.replace('**', ''))}</td>" for c in r) + "</tr>" for r in rows)
        parts.append(f"<section><h2>{e(title)}</h2><table><tr>{th}</tr>{tr}</table></section>")
    notes = "".join(f"<li>{e(n)}</li>" for n in NOTES)
    return f"""<!doctype html><html lang="ko"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1"><title>방어 전후 비교 결과</title>
<style>
:root{{--bg:#f6f7f9;--card:#fff;--text:#16181d;--muted:#6b7280;--line:#e5e7eb;--accent:#2563eb}}
@media (prefers-color-scheme:dark){{:root{{--bg:#0f1115;--card:#181b21;--text:#e8eaed;--muted:#9aa0a6;--line:#2a2e36;--accent:#60a5fa}}}}
body{{margin:0;background:var(--bg);color:var(--text);font:14px/1.6 -apple-system,"Segoe UI","Malgun Gothic",sans-serif}}
main{{max-width:900px;margin:0 auto;padding:24px 20px 48px}}h1{{font-size:20px}}h2{{font-size:15px;margin:0 0 10px}}
section{{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:14px 16px;margin:12px 0;overflow-x:auto}}
table{{width:100%;border-collapse:collapse}}th,td{{text-align:left;padding:7px 10px;border-bottom:1px solid var(--line)}}
th{{color:var(--muted);font-weight:600}}td:nth-child(3){{color:var(--accent);font-weight:600}}.muted{{color:var(--muted)}}
</style></head><body><main><h1>방어 전후 비교 결과</h1>
<p class="muted">측정 시각 {e(res['generated'])} · 더미 고객 {res['customers']:,}건</p>
{''.join(parts)}<section><h2>해석 시 유의사항</h2><ul>{notes}</ul></section></main></body></html>"""


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--customers", type=int, default=4000)
    args = ap.parse_args()
    res = {"generated": datetime.now(KST).strftime("%Y-%m-%d %H:%M KST"), "customers": args.customers,
           "scenarios": {}, "overhead": {}}
    for mode in ("off", "on"):
        print(f"[{mode}] 시나리오 실행 중...", flush=True)
        res["scenarios"][mode] = run_scenarios(mode, args.customers)
        print(f"[{mode}] 오버헤드 측정 중...", flush=True)
        res["overhead"][mode] = run_overhead(mode, args.customers)
    print("오탐·회피 분석 중...", flush=True)
    res["false_positive"] = run_false_positive()
    res["evasion"] = run_evasion()
    res["tradeoff"] = run_tradeoff()

    docs = ROOT / "docs"
    docs.mkdir(exist_ok=True)
    (docs / "benchmark.json").write_text(json.dumps(res, ensure_ascii=False, indent=2), encoding="utf-8")
    (docs / "benchmark.md").write_text(to_markdown(res), encoding="utf-8")
    (docs / "benchmark.html").write_text(to_html(res), encoding="utf-8")
    print(to_markdown(res))
    return res


if __name__ == "__main__":
    main()
