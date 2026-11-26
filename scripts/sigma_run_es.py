"""Sigma 규칙을 Elasticsearch(Lucene) 쿼리로 변환해 실제 ES에서 실행하고, 탐지 엔진이 남긴 결과와 비교한다 (선택 실행).

단일 이벤트 규칙(R2·R3·R7·R10)만 Lucene 백엔드로 변환된다. 상관 규칙(R1·R4·R5·R6)은 이 백엔드가 지원하지 않는다.
프로젝트 필수 의존성이 아니므로 별도 가상환경에서 실행한다.
  pip install "pysigma<2" pysigma-backend-elasticsearch httpx
  python scripts/sigma_run_es.py [--es http://127.0.0.1:9200]
먼저 docker compose up -d 후 scripts/attack_sim.py 와 scripts/demo_events.py 로 이벤트를 만들어 둔다.
"""
import argparse
import sys
from pathlib import Path

import httpx
from sigma.backends.elasticsearch import LuceneBackend
from sigma.collection import SigmaCollection

ROOT = Path(__file__).resolve().parent.parent

# (Sigma 파일, 규칙 ID, 설명)
RULES = [
    ("defense_inactive_account_access.yml", "R3", "비활성 계정 접근"),
    ("defense_export_preblock.yml", "R7", "내보내기 사전 차단"),
    ("defense_honeytoken_access.yml", "R10", "허니토큰 접근"),
    ("defense_offhours_data_access.yml", "R2", "새벽 접근 (local_hour)"),
]


def count(client, index, query):
    r = client.post(f"/{index}/_count", json={"query": {"query_string": {"query": query}}})
    r.raise_for_status()
    return r.json()["count"]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--es", default="http://127.0.0.1:9200")
    args = ap.parse_args()
    client = httpx.Client(base_url=args.es, timeout=30)
    ok = True
    for fname, rid, desc in RULES:
        col = SigmaCollection.from_yaml((ROOT / "sigma" / fname).read_text(encoding="utf-8"))
        query = LuceneBackend().convert(col)[0]
        n_sigma = count(client, "defense-audit-*", query)
        n_alerts = count(client, "defense-alerts-*", f"rule_id:{rid}")
        print(f"[{rid}] {desc}")
        print(f"   Lucene 쿼리: {query}")
        print(f"   Sigma 쿼리 결과: {n_sigma}건 / 탐지 엔진 경보: {n_alerts}건")
        if rid != "R2" and (n_alerts == 0) != (n_sigma == 0):
            ok = False
            print("   -> 불일치: 한쪽만 탐지함")
    print("\n결과:", "엔진과 Sigma 쿼리가 같은 사건을 탐지" if ok else "불일치 있음")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
