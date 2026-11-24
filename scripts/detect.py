"""감사 로그를 분석해 경보를 출력(및 저장)한다.

사용: python scripts/detect.py [--log 경로] [--save]
"""
import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app import config
from app.db import connect, init_db
from app.detection import Detector, load_events_from_file, save_alerts

ap = argparse.ArgumentParser()
ap.add_argument("--log", default=str(config.AUDIT_LOG_PATH))
ap.add_argument("--save", action="store_true", help="경보를 DB(alerts 테이블)에 저장")
args = ap.parse_args()

events = load_events_from_file(args.log)
alerts = Detector().run(events)
print(f"이벤트 {len(events)}건 분석, 경보 {len(alerts)}건")
for a in alerts:
    print(f"[{a.severity.upper():8}] {a.rule_id} {a.rule_name} | {a.user_key} | {a.ts} | {a.detail}")

if args.save:
    init_db()
    db = connect()
    try:
        print(f"DB 저장: 신규 {save_alerts(db, alerts)}건")
    finally:
        db.close()
