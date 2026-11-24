import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
DB_PATH = Path(os.environ.get("DEFENSE_DB", BASE_DIR / "data" / "app.db"))
AUDIT_LOG_PATH = Path(os.environ.get("DEFENSE_AUDIT_LOG", BASE_DIR / "logs" / "audit.jsonl"))
# 모의 환경 전용 키. 실제 서비스에서는 환경변수/비밀관리 서비스로 주입해야 한다.
JWT_SECRET = os.environ.get("DEFENSE_JWT_SECRET", "local-demo-only-secret-change-me-32bytes!")
JWT_ALG = "HS256"
JWT_TTL_MIN = 30
PAGE_SIZE_MAX = 50


def defense_enabled():
    """DEFENSE_MODE=off 이면 실시간 탐지·자동 차단을 끈다 (6일차 방어 전후 비교용)."""
    return os.environ.get("DEFENSE_MODE", "on").lower() != "off"


# 이 심각도 이상의 경보가 발생하면 해당 계정을 자동으로 잠근다
LOCK_SEVERITIES = {"high", "critical"}
