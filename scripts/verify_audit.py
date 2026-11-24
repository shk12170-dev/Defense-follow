"""감사 로그 파일의 변조 여부를 검증한다."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.audit import verify_chain

ok, line = verify_chain()
print("감사 로그 무결성 정상" if ok else f"변조 의심: {line}번째 줄")
sys.exit(0 if ok else 1)
