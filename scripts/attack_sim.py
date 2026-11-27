"""내부자 정보유출 공격 시뮬레이터 (로컬 모의 환경 + 더미 데이터 전용).

실제 공격 도구가 아니라, 정상 API를 정상 계정으로 호출해 '대량 조회·반출' 행동만 재현한다.
방어 장치(탐지·자동 차단)가 어느 시점에 개입하는지 보여주는 용도다.

사용: python scripts/attack_sim.py [--base http://127.0.0.1:8000] [--only 1 2 3 4]
시나리오: 1 대량 조회(R1) / 2 새벽 접근(R2, 오프라인 재생) / 3 퇴사자 계정(R3) / 4 대량 조회 후 반출(R4) / 5 분산 IP 비밀번호 스프레이(R13) / 6 토큰 탈취 후 다른 IP에서 사용(R14) / 7 관리자 마스킹 해제 반복(R15)
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
    print("\n=== 시나리오 4: 대량 조회 후 외부 반출 (R4·R7, 롯데카드형) ===")
    sim.reset_accounts(["admin01"])
    _, h = sim.login("admin01")
    for page in range(1, 6):
        r = sim.c.get(f"/customers?page={page}&size=50", headers=h)
        sim.log(f"조회 페이지 {page}: HTTP {r.status_code}")
    r = sim.c.get("/customers/export?limit=100&reason=월간 점검용 반출", headers=h)
    verdict = "사전 차단됨 (데이터 반환 없음)" if r.status_code == 403 else "반출 성공"
    sim.log(f"내보내기: HTTP {r.status_code} -> {verdict}")
    r = sim.c.get("/customers?page=1&size=50", headers=h)
    sim.log(f"이어서 조회: HTTP {r.status_code} ({r.json().get('detail', '응답 완료 - 누적 조회량에 따른 경보·잠금은 대시보드에서 확인')})")


def s5_spray(sim):
    print("\n=== 시나리오 5: 분산 IP 비밀번호 스프레이 (R13) ===")
    print("(여러 IP에서 한 계정에 한두 번씩 시도: IP마다는 스로틀 기준 아래라 R12를 피한다. X-Forwarded-For 위조를 이용하므로")
    print(" 서버를 DEFENSE_TRUSTED_PROXY=on 으로 띄운 로컬 시연에서만 의미가 있다)")
    sim.reset_accounts(["agent05"])
    codes = []
    for i in range(1, 13):
        r = sim.c.post("/auth/login", json={"username": "agent05", "password": f"guess-{i}"},
                       headers={"X-Forwarded-For": f"203.0.113.{i}"})
        codes.append(r.status_code)
    sim.log(f"12개 IP에서 각 1회 실패 시도: {sorted(set(codes))} (401만 나오면 스로틀에 걸리지 않음)")
    r, h = sim.login("agent05")  # 공격자가 마침내 올바른 비밀번호를 알아냈다고 가정
    sim.log(f"올바른 비밀번호로 로그인: HTTP {r.status_code}")
    if h:
        r = sim.c.get("/customers?page=1&size=10", headers=h)
        verdict = "추가 인증(TOTP) 없이는 데이터 접근 불가" if r.status_code == 428 else "데이터 접근 가능"
        sim.log(f"데이터 조회: HTTP {r.status_code} -> {verdict}")


def s6_token_theft(sim):
    print("\n=== 시나리오 6: 로그인 토큰 탈취 후 다른 IP에서 사용 (R14) ===")
    print("(정상 사용자와 공격자가 같은 토큰을 서로 다른 IP에서 쓴다. X-Forwarded-For 위조를 이용하므로")
    print(" 서버를 DEFENSE_TRUSTED_PROXY=on 으로 띄운 로컬 시연에서만 의미가 있다)")
    sim.reset_accounts(["agent02"])
    legit, thief = {"X-Forwarded-For": "198.51.100.10"}, {"X-Forwarded-For": "203.0.113.99"}
    r = sim.c.post("/auth/login", json={"username": "agent02", "password": DEMO_PASSWORD}, headers=legit)
    token = {"Authorization": f"Bearer {r.json()['access_token']}"}
    r = sim.c.get("/customers?page=1&size=20", headers={**token, **legit})
    sim.log(f"정상 사용자(IP 198.51.100.10) 조회: HTTP {r.status_code}")
    got = 0
    for i in range(1, 6):
        r = sim.c.get(f"/customers?page={i + 1}&size=50", headers={**token, **thief})
        if r.status_code != 200:
            sim.log(f"탈취한 토큰(IP 203.0.113.99) 요청 {i}: HTTP {r.status_code} -> 차단됨 ({r.json().get('detail')})")
            break
        got += len(r.json()["items"])
        sim.log(f"탈취한 토큰(IP 203.0.113.99) 요청 {i}: 누적 {got}건 확보")
    print(f"결과: 토큰만 가진 공격자는 {got}건 확보 후 차단 (인증 코드가 없어 재인증을 통과할 수 없음)")
    r = sim.c.get("/customers?page=1&size=10", headers={**token, **legit})
    sim.log(f"같은 계정의 정상 사용자 다음 요청: HTTP {r.status_code} (토큰을 발급받은 IP의 정상 사용자는 계속 사용 가능, 428이면 다른 규칙의 재인증 상태)")


def s7_unmask(sim):
    print("\n=== 시나리오 7: 관리자 계정의 마스킹 해제(주민번호 원문) 반복 (R15) ===")
    print("(사유만 적으면 원문이 열리므로 사유로는 남용을 막지 못한다. 서버는 원문을 연 횟수를 세어 재인증을 요구한다)")
    sim.reset_accounts(["admin01"])
    _, h = sim.login("admin01")
    got = 0
    for cid in range(1, 31):
        r = sim.c.get(f"/customers/{cid}?unmask=true&reason=월간 점검용 확인", headers=h)
        if r.status_code != 200:
            sim.log(f"원문 조회 {cid}번째: HTTP {r.status_code} -> 차단됨 ({r.json().get('detail')})")
            break
        got += 1
    print(f"결과: 원문 {got}건 확보 후 차단 (재인증 코드가 없으면 이후 조회 불가, 서버 하드 쿼터는 하루 20건)")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default="http://127.0.0.1:8000")
    ap.add_argument("--only", nargs="*", type=int, default=[1, 2, 3, 4, 5, 6, 7])
    args = ap.parse_args()
    sim = Sim(args.base)
    steps = {1: s1_bulk, 2: s2_off_hours, 3: s3_dormant, 4: s4_exfil, 5: s5_spray, 6: s6_token_theft, 7: s7_unmask}
    for n in args.only:
        steps[n](sim)
    print("\n경보 확인: GET /alerts (admin 로그인 필요)")


if __name__ == "__main__":
    main()
