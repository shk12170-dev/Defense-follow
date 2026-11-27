"""R14(다중 IP 동시 사용) 오탐·탐지 민감도 측정.

합성 업무 로그(benchmark.normal_events)에는 접속 IP가 하나뿐이라 R14 오탐을 잴 수 없었다.
여기서는 정상 사용자의 네트워크 전환(사무실 Wi-Fi -> 모바일 핫스팟 등)을 가정해 IP를 바꿔 넣고,
창 길이(window_min)별로 (1) 정상 사용자 오탐 상담원-일, (2) 탈취 토큰 탐지 여부를 같은 엔진으로 잰다.
전환 빈도는 실제 측정값이 아니라 가정이다(결과는 가정별 표로만 해석한다).

사용: python scripts/r14_study.py
"""
import copy
import random
import sys
from datetime import datetime, timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from app.detection import Detector, load_rules  # noqa: E402
sys.path.insert(0, str(Path(__file__).resolve().parent))
from benchmark import normal_events  # noqa: E402

WINDOWS = (2, 5, 10, 30)
SWITCH_RATES = (0.0, 0.05, 0.2)   # 상담원-일 당 네트워크 전환이 일어날 확률(가정)
GAPS = (1, 5, 10, 20)             # 정상 사용자의 마지막 요청 후 공격자가 같은 토큰을 쓰기까지의 분


def detector(window):
    cfg = copy.deepcopy(load_rules())
    for r in cfg["rules"]:
        if r["id"] == "R14":
            r["window_min"] = window
    return Detector(cfg)


def with_switches(events, rate, seed=11):
    """상담원-일마다 확률 rate로 하루 중 임의 시점에 IP가 바뀐다(이후 같은 날 요청은 새 IP)."""
    rnd = random.Random(seed)
    by_day = {}
    for e in events:
        by_day.setdefault((e["username"], e["ts"][:10]), []).append(e)
    out = []
    for (user, _), evs in by_day.items():
        evs.sort(key=lambda e: e["ts"])
        cut = rnd.randrange(len(evs)) if rnd.random() < rate else None
        for i, e in enumerate(evs):
            e = dict(e)
            if cut is not None and i >= cut:
                e["ip"] = "172.20.10.2"
            out.append(e)
    return sorted(out, key=lambda e: e["ts"])


def false_positives(window, rate):
    evs = with_switches(normal_events(), rate)
    alerts = [a for a in detector(window).run(evs) if a.rule_id == "R14"]
    return len({(a.user_key, str(a.ts)[:10]) for a in alerts}), len(alerts)


def detects(window, gap_min):
    base = datetime(2026, 10, 5, 10, 0)
    def ev(t, ip):
        return {"ts": t.isoformat() + "+09:00", "username": "agent01", "action": "customer.list", "result": "ok",
                "rows": 20, "detail": None, "ip": ip, "resource": None}
    evs = [ev(base, "10.0.0.5"), ev(base + timedelta(minutes=gap_min), "203.0.113.99")]
    return any(a.rule_id == "R14" for a in detector(window).run(evs))


def main():
    agent_days = 30 * 5
    print(f"## 오탐 (정상 사용자 네트워크 전환 가정, 합성 30일 {agent_days} 상담원-일)")
    print("| 창(분) | " + " | ".join(f"전환 {int(r * 100)}%/일" for r in SWITCH_RATES) + " |")
    print("|---|" + "---|" * len(SWITCH_RATES))
    for w in WINDOWS:
        cells = []
        for r in SWITCH_RATES:
            d, _ = false_positives(w, r)
            cells.append(f"{d}건 ({d / agent_days * 100:.1f}%)")
        print(f"| {w} | " + " | ".join(cells) + " |")
    print("\n## 탈취 토큰 탐지 (정상 마지막 요청 후 N분 뒤 공격자 첫 요청)")
    print("| 창(분) | " + " | ".join(f"{g}분 뒤" for g in GAPS) + " |")
    print("|---|" + "---|" * len(GAPS))
    for w in WINDOWS:
        print(f"| {w} | " + " | ".join("탐지" if detects(w, g) else "놓침" for g in GAPS) + " |")


if __name__ == "__main__":
    main()
