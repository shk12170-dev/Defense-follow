"""Kibana 초기 설정: 데이터 뷰, 저장된 검색, 대시보드를 만든다. 여러 번 실행해도 안전하다(덮어쓰기).

사용: KIBANA_URL=http://localhost:5601 python scripts/kibana_setup.py
"""
import json
import os
import sys
import time

import httpx

AUDIT_VIEW = "defense-audit"
ALERTS_VIEW = "defense-alerts"
DASHBOARD_ID = "defense-overview"
HEADERS = {"kbn-xsrf": "true", "Content-Type": "application/json"}

DATA_VIEWS = [
    (AUDIT_VIEW, "defense-audit-*", "Defense 감사 로그"),
    (ALERTS_VIEW, "defense-alerts-*", "Defense 경보"),
]

# (id, 제목, 데이터 뷰, KQL, 표시 컬럼)
SEARCHES = [
    ("defense-s-alerts", "경보 전체", ALERTS_VIEW, "",
     ["severity", "rule_id", "rule_name", "username", "mitre", "detail"]),
    ("defense-s-alerts-high", "high·critical 경보", ALERTS_VIEW, "severity:high or severity:critical",
     ["severity", "rule_id", "username", "detail"]),
    ("defense-s-locks", "자동 잠금 이벤트", AUDIT_VIEW, 'action:"response.lock"',
     ["username", "resource", "detail"]),
    ("defense-s-inactive", "R3 후보: 비활성 계정 접근", AUDIT_VIEW,
     '(action:"auth.login" and result:"denied") or detail:"inactive account"',
     ["username", "action", "result", "detail", "ip"]),
    ("defense-s-bulk", "R1 후보: 50건 이상 한 번에 조회", AUDIT_VIEW, 'result:"ok" and rows >= 50',
     ["username", "action", "rows", "resource"]),
    ("defense-s-offhours", "R2 후보: 새벽(00~05시 KST) 접근", AUDIT_VIEW,
     'result:"ok" and local_hour < 6 and action:customer*', ["username", "action", "local_hour", "resource"]),
    ("defense-s-failed", "로그인 실패", AUDIT_VIEW, 'action:"auth.login" and result:"failed"',
     ["username", "detail", "ip"]),
    # ---- 2차 보완(R5~R7) ----
    ("defense-s-r5", "R5 경고: 일일 누적 조회 (잠금 없음)", ALERTS_VIEW, 'rule_id:"R5"',
     ["severity", "username", "detail"]),
    ("defense-s-r6", "R6 차단: 일일 누적 조회 (계정 잠금)", ALERTS_VIEW, 'rule_id:"R6"',
     ["severity", "username", "detail"]),
    ("defense-s-r7", "R7: 대량 조회 직후 내보내기 사전 차단", AUDIT_VIEW,
     'action:"customer.export" and result:"blocked"', ["username", "detail", "ip"]),
    ("defense-s-warn", "단계적 대응: 경고 이벤트 (잠금 없음)", AUDIT_VIEW, 'action:"response.warn"',
     ["username", "resource", "detail"]),
]


def wait_ready(client, timeout=180, interval=3):
    """Kibana가 요청을 받을 수 있을 때까지 기다린다."""
    deadline = time.time() + timeout
    while True:
        try:
            r = client.get("/api/status")
            if r.status_code == 200 and r.json().get("status", {}).get("overall", {}).get("level") == "available":
                return True
        except httpx.HTTPError:
            pass
        if time.time() >= deadline:
            raise TimeoutError("Kibana가 준비되지 않았습니다")
        time.sleep(interval)


def create_data_views(client):
    for vid, pattern, name in DATA_VIEWS:
        body = {"data_view": {"id": vid, "title": pattern, "name": name, "timeFieldName": "@timestamp"},
                "override": True}
        r = client.post("/api/data_views/data_view", content=json.dumps(body), headers=HEADERS)
        r.raise_for_status()


def search_object(title, view_id, query, columns):
    source = {"query": {"query": query, "language": "kuery"}, "filter": [],
              "indexRefName": "kibanaSavedObjectMeta.searchSourceJSON.index"}
    return {
        "attributes": {
            "title": title, "description": "", "columns": columns, "sort": [["@timestamp", "desc"]],
            "grid": {}, "hideChart": False,
            "kibanaSavedObjectMeta": {"searchSourceJSON": json.dumps(source)},
        },
        "references": [{"name": "kibanaSavedObjectMeta.searchSourceJSON.index", "type": "index-pattern", "id": view_id}],
    }


def create_searches(client):
    for sid, title, view, query, cols in SEARCHES:
        r = client.post(f"/api/saved_objects/search/{sid}?overwrite=true",
                        content=json.dumps(search_object(title, view, query, cols)), headers=HEADERS)
        r.raise_for_status()


def dashboard_object():
    panels, refs = [], []
    for i, (sid, *_rest) in enumerate(SEARCHES, 1):
        panels.append({"version": "8.15.3", "type": "search", "panelIndex": str(i),
                       "gridData": {"x": 0 if i % 2 else 24, "y": ((i - 1) // 2) * 15, "w": 24, "h": 15, "i": str(i)},
                       "embeddableConfig": {}, "panelRefName": f"panel_{i}"})
        refs.append({"name": f"panel_{i}", "type": "search", "id": sid})
    return {
        "attributes": {
            "title": "Defense 보안 관제", "description": "내부자 정보유출 탐지·대응 현황",
            "panelsJSON": json.dumps(panels),
            "optionsJSON": json.dumps({"useMargins": True, "syncColors": False, "hidePanelTitles": False}),
            "timeRestore": False,
            "kibanaSavedObjectMeta": {"searchSourceJSON": json.dumps({"query": {"query": "", "language": "kuery"}, "filter": []})},
        },
        "references": refs,
    }


def create_dashboard(client):
    r = client.post(f"/api/saved_objects/dashboard/{DASHBOARD_ID}?overwrite=true",
                    content=json.dumps(dashboard_object()), headers=HEADERS)
    r.raise_for_status()


def run(client, wait=True):
    if wait:
        wait_ready(client)
    create_data_views(client)
    create_searches(client)
    create_dashboard(client)


def main():
    url = os.environ.get("KIBANA_URL", "http://localhost:5601")
    with httpx.Client(base_url=url, timeout=30) as client:
        run(client)
    print(f"Kibana 설정 완료: {url}/app/dashboards#/view/{DASHBOARD_ID}")


if __name__ == "__main__":
    try:
        main()
    except Exception as e:  # noqa: BLE001
        print(f"Kibana 설정 실패: {e}", file=sys.stderr)
        sys.exit(1)
