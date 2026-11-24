"""내부자 정보유출 공격 시뮬레이터 (로컬 모의 환경 + 더미 데이터 전용).

실제 공격 도구가 아니라, 정상 API를 정상 계정으로 호출해 '대량 조회·반출' 행동만 재현한다.
방어 장치(탐지·자동 차단)가 어느 시점에 개입하는지 보여주는 용도다.

사용: python scripts/attack_sim.py [--base http://127.0.0.1:8000] [--only 1 2 3 4]
시나리오: 1 대량 조회(R1) / 2 새벽 접근(R2, 오프라인 재생) / 3 퇴사자 계정(R3) / 4 대량 조회 후 반출(R4)
"""
import argparse
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from app.detection import Detector  # noqa: E402

DEMO_PASSWORD = "Demo#2026pw"  # scripts/seed.py의 더미 비밀번호와 동일


class Sim:
    def __init__(self, base):
        self.c = httpx.Client(base_url=base, timeout=30)
        self.t0 = time.time()

    def log(self, msg):
        print(f"[{time.time() - self.t0:6.2f}s] {msg}", flush=True)

    def login(self, user):
        r = self.c.post("/auth/login", json={"username": user, "password": DEMO_PASSWORD})
        return r, ({"Authorization": f"Bearer {r.json()['access_token']}"} if r.status_code == 200 else None)

    def reset_accounts(self, users):
        """이전 시연으로 잠긴 계정을 관리자(admin02)가 해제한다."""
        _, h = self.login("admin02")
        for u in users:
            r = self.c.post(f"/admin/users/{u}/unlock", headers=h)
            if r.status_code == 200:
                self.log(f"(준비) {u} 잠금 해제")


def s1_bulk(sim):
    print("\n=== 시나리오 1: 상담원의 대량 조회 (R1, 쿠팡형) ===")
    sim.reset_accounts(["agent01"])
    _, h = sim.login("agent01")
    got = 0
    for page in range(1, 31):
        r = sim.c.get(f"/customers?page={page}&size=50", headers=h)
        if r.status_code != 200:
            sim.log(f"페이지 {page}: HTTP {r.status_code} -> 차단됨 ({r.json().get('detail')})")
            break
        got += len(r.json()["items"])
        sim.log(f"페이지 {page}: 누적 {got}건 확보")
    print(f"결과: 총 {got}건 확보 후 차단 (방어 없이 30페이지 조회 시 최대 1,500건)")
    return got


def s2_off_hours(sim):
    print("\n=== 시나리오 2: 새벽 시간대 접근 (R2, 오프라인 재생) ===")
    kst = timezone(timedelta(hours=9))
    ts = datetime(2026, 11, 20, 2, 30, tzinfo=kst).astimezone(timezone.utc).isoformat()
    ev = {"ts": ts, "username": "agent02", "action": "customer.view", "result": "ok", "rows": 1,
          "detail": None, "ip": "10.0.0.7", "resource": "customer/1"}
    alerts = Detector().run([ev])
    for a in alerts:
        print(f"경보 {a.rule_id} {a.rule_name} ({a.severity}): {a.detail}")
    print("(서버 시계를 바꿀 수 없어 합성 이벤트를 탐지 엔진에 재생했습니다)")
    return alerts


def s3_dormant(sim):
    print("\n=== 시나리오 3: 퇴사자 계정 접근 (R3) ===")
    for u in ("retired01", "dormant01"):
        r, _ = sim.login(u)
        sim.log(f"{u} 로그인 시도: HTTP {r.status_code} ({r.json().get('detail')})")


def s4_exfil(sim):
    print("\n=== 시나리오 4: 대량 조회 후 외부 반출 (R4, 롯데카드형) ===")
    sim.reset_accounts(["admin01"])
    _, h = sim.login("admin01")
    for page in range(1, 6):
        r = sim.c.get(f"/customers?page={page}&size=50", headers=h)
        sim.log(f"조회 페이지 {page}: HTTP {r.status_code}")
    r = sim.c.get("/customers/export?limit=100&reason=월간 점검용 반출", headers=h)
    sim.log(f"내보내기: HTTP {r.status_code}")
    r = sim.c.get("/customers?page=1&size=50", headers=h)
    sim.log(f"반출 직후 재접속: HTTP {r.status_code} ({r.json().get('detail')})")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default="http://127.0.0.1:8000")
    ap.add_argument("--only", nargs="*", type=int, default=[1, 2, 3, 4])
    args = ap.parse_args()
    sim = Sim(args.base)
    steps = {1: s1_bulk, 2: s2_off_hours, 3: s3_dormant, 4: s4_exfil}
    for n in args.only:
        steps[n](sim)
    print("\n경보 확인: GET /alerts (admin 로그인 필요)")


if __name__ == "__main__":
    main()
