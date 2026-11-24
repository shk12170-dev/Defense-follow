"""컨테이너 시작 스크립트: DB가 없으면 더미 데이터를 만든 뒤 서버를 실행한다."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import uvicorn

from app import config

if not config.DB_PATH.exists():
    from scripts import seed
    seed.main()

# 컨테이너 안에서는 0.0.0.0으로 열되, 호스트 쪽 공개 범위는 docker-compose에서 127.0.0.1로 제한한다.
uvicorn.run("app.main:app", host="0.0.0.0", port=8000)
