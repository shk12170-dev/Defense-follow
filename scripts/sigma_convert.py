"""sigma/ 의 규칙을 pySigma로 변환해 쿼리를 출력한다 (변환 가능 여부 검증용, 선택 실행).

프로젝트 필수 의존성이 아니므로 별도 가상환경에서 설치해 실행한다.
  pip install pysigma pysigma-backend-splunk
  python scripts/sigma_convert.py
상관(correlation) 규칙은 Splunk 백엔드가 변환한다(Elasticsearch Lucene 백엔드는 상관 규칙 미지원).
"""
import glob
import sys
from pathlib import Path

from sigma.backends.splunk import SplunkBackend
from sigma.collection import SigmaCollection

ROOT = Path(__file__).resolve().parent.parent


def main():
    failed = 0
    for f in sorted(glob.glob(str(ROOT / "sigma" / "*.yml"))):
        print("==", Path(f).name)
        try:
            col = SigmaCollection.from_yaml(Path(f).read_text(encoding="utf-8"))
            for q in SplunkBackend().convert(col):
                print("  ", q)
            if col.errors:
                raise ValueError(col.errors)
        except Exception as e:  # noqa: BLE001
            failed += 1
            print("  실패:", type(e).__name__, e)
    print(f"\n변환 실패 {failed}건")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
