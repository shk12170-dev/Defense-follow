import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
DB_PATH = Path(os.environ.get("DEFENSE_DB", BASE_DIR / "data" / "app.db"))
AUDIT_LOG_PATH = Path(os.environ.get("DEFENSE_AUDIT_LOG", BASE_DIR / "logs" / "audit.jsonl"))
ALERT_LOG_PATH = Path(os.environ.get("DEFENSE_ALERT_LOG", BASE_DIR / "logs" / "alerts.jsonl"))
# 모의 환경 전용 키. 실제 서비스에서는 환경변수/비밀관리 서비스로 주입해야 한다.
JWT_SECRET = os.environ.get("DEFENSE_JWT_SECRET", "local-demo-only-secret-change-me-32bytes!")
DATA_KEY = os.environ.get("DEFENSE_DATA_KEY", "")  # 민감정보 암호화 키(Fernet). 비어 있으면 모의 환경용 기본 키
JWT_ALG = "HS256"
JWT_TTL_MIN = 30
PAGE_SIZE_MAX = 50


def export_approval_required():
    """DEFENSE_EXPORT_APPROVAL=on 이면 내보내기에 다른 관리자의 승인이 필요하다 (기본 꺼짐: 옵션 강화 모드)."""
    return os.environ.get("DEFENSE_EXPORT_APPROVAL", "off").lower() == "on"


EXPORT_APPROVAL_TTL_MIN = 15  # 승인 후 이 시간 안에 한 번만 내려받을 수 있다


def defense_enabled():
    """DEFENSE_MODE=off 이면 실시간 탐지·자동 차단을 끈다 (6일차 방어 전후 비교용)."""
    return os.environ.get("DEFENSE_MODE", "on").lower() != "off"


# 이 심각도 이상의 경보가 발생하면 해당 계정을 자동으로 잠근다
LOCK_SEVERITIES = {"high", "critical"}
