"""더미 데이터 생성. 실제 개인정보가 아닌 무작위 가짜 값만 만든다."""
import random
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app import config
from app.db import connect, init_db
from app.security import hash_password

DECOY_AFTER = 0.4   # 앞쪽 40%에는 심지 않는다 (소규모 업무·내보내기 100건이 닿지 않도록)
DECOY_EVERY = 400   # 이 간격마다 1건
DEMO_PASSWORD = "Demo#2026pw"  # 로컬 모의 환경 전용 더미 비밀번호
SURNAMES = list("김이박최정강조윤장임한오서신권황안송류홍")
GIVEN = ["민준", "서연", "도윤", "지우", "하준", "서윤", "예준", "지민", "시우", "수아", "주원", "하은", "지호", "채원", "건우"]
CITIES = ["서울특별시 강남구", "서울특별시 마포구", "부산광역시 해운대구", "대구광역시 수성구",
          "인천광역시 연수구", "대전광역시 유성구", "광주광역시 북구", "경기도 성남시", "경기도 수원시"]

USERS = [
    ("agent01", "agent", "active"), ("agent02", "agent", "active"), ("agent03", "agent", "active"),
    ("agent04", "agent", "active"), ("agent05", "agent", "active"),
    ("admin01", "admin", "active"), ("admin02", "admin", "active"),  # admin02: 잠금 해제 담당 (admin01이 잠겨도 복구 가능)
    ("dba01", "dba", "active"),
    ("retired01", "agent", "dormant"),  # 퇴사자 계정 (탐지 규칙 3 시나리오)
    ("dormant01", "agent", "dormant"),  # 휴면 계정
]


def main(n_customers=10_000, seed=2026):
    rnd = random.Random(seed)
    if config.DB_PATH.exists():
        config.DB_PATH.unlink()
    init_db()
    db = connect()
    try:
        pw_hash = hash_password(DEMO_PASSWORD)
        for name, role, status in USERS:
            db.execute("INSERT INTO users(username,password_hash,role,status) VALUES(?,?,?,?)",
                       (name, pw_hash, role, status))
        agents = [r["id"] for r in db.execute("SELECT id FROM users WHERE username LIKE 'agent0%' AND status='active'")]
        rows = []
        for i in range(n_customers):
            name = rnd.choice(SURNAMES) + rnd.choice(GIVEN)
            phone = f"010-{rnd.randint(1000, 9999)}-{rnd.randint(1000, 9999)}"
            email = f"user{i:05d}@example.com"
            rrn = f"{rnd.randint(70, 99):02d}{rnd.randint(1, 12):02d}{rnd.randint(1, 28):02d}-{rnd.choice('1234')}{rnd.randint(0, 999999):06d}"
            addr = f"{rnd.choice(CITIES)} {rnd.randint(1, 300)}번길 {rnd.randint(1, 99)}"
            rows.append((name, phone, email, rrn, addr, rnd.choice(agents)))
        db.executemany("INSERT INTO customers(name,phone,email,rrn,address,assigned_agent_id) VALUES(?,?,?,?,?,?)", rows)
        # 허니토큰(미끼 고객): 정상 업무로는 열 일이 없는 위치(전체의 뒤쪽 60% 구간, 담당 상담원 없음)에 심는다.
        # 상담원 화면에는 나오지 않고, 관리자의 전수 조회·내보내기·ID 순차 조회에서만 닿는다.
        db.execute("UPDATE customers SET decoy=1, assigned_agent_id=NULL WHERE id > ? AND id % ? = 0",
                   (int(n_customers * DECOY_AFTER), DECOY_EVERY))
        db.commit()
    finally:
        db.close()
    print(f"seed 완료: users={len(USERS)}, customers={n_customers}")


if __name__ == "__main__":
    main()
