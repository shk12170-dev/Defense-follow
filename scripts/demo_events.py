"""3차 보완 기능(R10 허니토큰, R11 ID 탐색, 단계적 재인증)의 이벤트를 만드는 시연 스크립트.

로컬 모의 환경 전용. 정상 API를 정상 계정으로 호출해 행동만 재현한다.
사용: python scripts/demo_events.py [--base http://127.0.0.1:8000]
(R9 쿼터 소진은 R1·R5 때문에 빠른 호출로는 도달할 수 없어 이 스크립트에 포함하지 않는다.)
"""
import argparse
import sys
from pathlib import Path

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from app.totp import code_for, new_secret  # noqa: E402

PW = "Demo#2026pw"  # scripts/seed.py의 더미 비밀번호


def login(c, user):
    r = c.post("/auth/login", json={"username": user, "password": PW})
    r.raise_for_status()
    return {"Authorization": "Bearer " + r.json()["access_token"]}


def clear_stepup_if_needed(c, h, user):
    """이전 시연으로 재인증 대기 상태라면 TOTP+사유로 먼저 통과시킨다."""
    if c.get("/customers?page=1&size=1", headers=h).status_code == 428:
        r = c.post("/auth/stepup", json={"code": code_for(new_secret(f"demo-mfa-{user}")),
                                          "reason": "시연 준비를 위한 재인증"}, headers=h)
        print(f"  ({user} 재인증 대기 상태였음 -> {r.json()['status']})")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default="http://127.0.0.1:8000")
    c = httpx.Client(base_url=ap.parse_args().base, timeout=30)

    print("[R11] agent03: 담당이 아닌 고객 ID를 순차로 조회")
    h = login(c, "agent03")
    codes = [c.get(f"/customers/{i}", headers=h).status_code for i in range(1, 41)]
    print("  응답 코드:", sorted(set(codes)), "-> 428이 나오면 재인증 요구로 차단됨")

    print("[재인증] agent04: 대량 조회 -> 재인증 요구 -> TOTP+사유로 재인증 -> 재개")
    h = login(c, "agent04")
    for p in range(1, 8):
        c.get(f"/customers?page={p}&size=50", headers=h)
    print("  재인증 전:", c.get("/customers?page=8&size=10", headers=h).status_code)
    ok = c.post("/auth/stepup", json={"code": code_for(new_secret("demo-mfa-agent04")),
                                      "reason": "고객 일괄 문의 처리 업무"}, headers=h)
    print("  재인증:", ok.json())
    print("  재인증 후:", c.get("/customers?page=8&size=10", headers=h).status_code)

    print("[R10] admin01: 목록 깊은 페이지로 건너뛰다 허니토큰(미끼 고객)을 만남")
    h = login(c, "admin01")
    clear_stepup_if_needed(c, h, "admin01")
    r = c.get("/customers?page=88&size=50", headers=h)  # id 4351~4400 구간 (미끼 4400 포함)
    print("  응답:", r.status_code, "-> 이후 요청:", c.get("/me", headers=h).status_code, "(403이면 즉시 잠김)")


if __name__ == "__main__":
    main()
