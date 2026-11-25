"""ELK·Docker 연동 산출물 검증. 도커 엔진 없이 구성 파일의 정합성과 Sigma 규칙의 동작을 확인한다."""
import json
import re
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import httpx
import pytest
import yaml

from app.detection import Alert, Detector, save_alerts
from scripts import kibana_setup as ks

ROOT = Path(__file__).resolve().parent.parent
KST = timezone(timedelta(hours=9))


def load(path):
    return yaml.safe_load((ROOT / path).read_text(encoding="utf-8"))


# ---------- 경보 로그 파일 ----------
def test_alert_log_written_only_for_new_alerts(tmp_path, monkeypatch):
    import importlib
    monkeypatch.setenv("DEFENSE_DB", str(tmp_path / "t.db"))
    monkeypatch.setenv("DEFENSE_ALERT_LOG", str(tmp_path / "alerts.jsonl"))
    from app import config
    importlib.reload(config)
    from app import db as dbm
    importlib.reload(dbm)
    dbm.init_db()
    a = Alert("2026-11-25T01:00:00.000+00:00", "R1", "대량 조회", "high", "T1213", "agent01", "agent01", {"rows_in_window": 300})
    conn = dbm.connect()
    assert save_alerts(conn, [a]) == 1
    assert save_alerts(conn, [a]) == 0  # 중복은 파일에도 다시 쓰지 않는다
    conn.close()
    lines = config.ALERT_LOG_PATH.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 1
    rec = json.loads(lines[0])
    assert rec["rule_id"] == "R1" and rec["detail"] == {"rows_in_window": 300} and rec["ts"].endswith("+00:00")


# ---------- docker-compose ----------
def test_compose_structure_and_local_only_ports():
    c = load("docker-compose.yml")
    assert {"app", "elasticsearch", "kibana", "filebeat", "kibana-setup"} <= set(c["services"])
    for name, svc in c["services"].items():
        for p in svc.get("ports", []):
            assert p.startswith("127.0.0.1:"), f"{name}의 포트 {p}가 로컬 전용이 아님"
        img = svc.get("image", "")
        assert not img.endswith(":latest"), f"{name} 이미지 버전 고정 필요"
    es = c["services"]["elasticsearch"]["environment"]
    assert es["discovery.type"] == "single-node"
    # 모든 볼륨 참조가 선언돼 있어야 한다
    used = {v.split(":")[0] for s in c["services"].values() for v in s.get("volumes", []) if not v.startswith(".")}
    assert used <= set(c["volumes"])
    # ELK 버전 일치
    vers = {c["services"][s]["image"].rsplit(":", 1)[1] for s in ("elasticsearch", "kibana", "filebeat")}
    assert len(vers) == 1


def test_compose_filebeat_reads_app_logs_volume():
    c = load("docker-compose.yml")
    fb_vols = c["services"]["filebeat"]["volumes"]
    assert "app-logs:/logs:ro" in fb_vols and "app-logs:/app/logs" in c["services"]["app"]["volumes"]


def test_dockerfile_runs_as_non_root_and_copies_runtime_dirs():
    text = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    assert "USER appuser" in text and "COPY rules rules" in text and "COPY app app" in text
    assert "scripts/docker_start.py" in text


# ---------- Filebeat ----------
def test_filebeat_config():
    fb = load("elk/filebeat.yml")
    inputs = {i["id"]: i for i in fb["filebeat.inputs"]}
    assert inputs["defense-audit"]["paths"] == ["/logs/audit.jsonl"]
    assert inputs["defense-alerts"]["paths"] == ["/logs/alerts.jsonl"]
    ts = next(p["timestamp"] for p in fb["processors"] if "timestamp" in p)
    assert ts["field"] == "ts" and ts["layouts"] == ["2006-01-02T15:04:05.999Z07:00"]
    streams = {i["when.equals"]["stream"]: i["index"] for i in fb["output.elasticsearch"]["indices"]}
    assert streams == {"alerts": "defense-alerts-%{+yyyy.MM.dd}", "audit": "defense-audit-%{+yyyy.MM.dd}"}
    assert fb["setup.template.pattern"] == "defense-*"
    # 데이터 스트림 방식이 켜져 있으면 일반 인덱스 이름과 충돌해 이벤트가 버려진다 (실제 기동에서 확인된 문제)
    assert fb["setup.ilm.enabled"] is False and fb["setup.dsl.enabled"] is False
    # ECS 기본 템플릿에서 객체인 hash 필드와 충돌하므로 이름을 바꿔 보낸다 (실제 기동에서 확인된 문제)
    rename = next(p["rename"] for p in fb["processors"] if "rename" in p)
    assert {"from": "hash", "to": "chain_hash"} in rename["fields"]


def test_data_view_patterns_match_filebeat_indices():
    fb = load("elk/filebeat.yml")
    indices = [i["index"].replace("%{+yyyy.MM.dd}", "2026.11.25") for i in fb["output.elasticsearch"]["indices"]]
    for _vid, pattern, _name in ks.DATA_VIEWS:
        rx = re.compile("^" + pattern.replace("*", ".*") + "$")
        assert any(rx.match(i) for i in indices), pattern


# ---------- Kibana 설정 스크립트 ----------
def make_client(handler):
    return httpx.Client(base_url="http://kibana.test", transport=httpx.MockTransport(handler))


def test_kibana_setup_creates_views_searches_dashboard():
    calls = []

    def handler(req):
        calls.append((req.method, req.url.path, req.url.query.decode(), json.loads(req.content or b"{}")))
        assert req.headers["kbn-xsrf"] == "true"
        return httpx.Response(200, json={})

    with make_client(handler) as c:
        ks.run(c, wait=False)
    views = [b for m, p, q, b in calls if p == "/api/data_views/data_view"]
    assert {v["data_view"]["id"] for v in views} == {"defense-audit", "defense-alerts"}
    assert all(v["override"] is True and v["data_view"]["timeFieldName"] == "@timestamp" for v in views)
    searches = [(p, q, b) for m, p, q, b in calls if p.startswith("/api/saved_objects/search/")]
    assert len(searches) == len(ks.SEARCHES)
    assert all(q == "overwrite=true" for _p, q, _b in searches)
    for _p, _q, b in searches:
        assert b["references"][0]["id"] in {"defense-audit", "defense-alerts"}
        assert json.loads(b["attributes"]["kibanaSavedObjectMeta"]["searchSourceJSON"])["query"]["language"] == "kuery"
    dash = next(b for m, p, q, b in calls if p.startswith("/api/saved_objects/dashboard/"))
    panels = json.loads(dash["attributes"]["panelsJSON"])
    assert len(panels) == len(ks.SEARCHES) == len(dash["references"])
    assert {r["id"] for r in dash["references"]} == {s[0] for s in ks.SEARCHES}
    assert {p["panelRefName"] for p in panels} == {r["name"] for r in dash["references"]}


def test_kibana_setup_fails_loudly_on_error():
    with make_client(lambda req: httpx.Response(500, json={"error": "x"})) as c:
        with pytest.raises(httpx.HTTPStatusError):
            ks.run(c, wait=False)


def test_wait_ready():
    state = {"n": 0}

    def handler(req):
        state["n"] += 1
        level = "available" if state["n"] >= 3 else "unavailable"
        return httpx.Response(200, json={"status": {"overall": {"level": level}}})

    with make_client(handler) as c:
        assert ks.wait_ready(c, timeout=5, interval=0) is True
    with make_client(lambda req: httpx.Response(503)) as c:
        with pytest.raises(TimeoutError):
            ks.wait_ready(c, timeout=0, interval=0)


def test_searches_use_fields_that_logs_actually_have():
    """저장된 검색이 참조하는 필드가 실제 로그에 존재하는지 확인한다."""
    audit_fields = {"ts", "user_id", "username", "role", "action", "resource", "detail", "ip", "result", "rows",
                    "chain_prev", "chain_hash", "local_hour", "@timestamp", "stream"}
    alert_fields = {"ts", "rule_id", "rule_name", "severity", "mitre", "user_key", "username", "detail", "@timestamp", "stream"}
    for _sid, _title, view, query, cols in ks.SEARCHES:
        allowed = audit_fields if view == "defense-audit" else alert_fields
        assert set(cols) <= allowed, (_title, set(cols) - allowed)
        for f in re.findall(r"\b([a-z_]+)\s*(?::|>=|<=|<|>)", query):
            if f in ("and", "or", "not"):
                continue
            assert f in allowed, (_title, f)


# ---------- Sigma ----------
def sigma_docs():
    docs = []
    for p in sorted((ROOT / "sigma").glob("*.yml")):
        docs += [(p.name, d) for d in yaml.safe_load_all(p.read_text(encoding="utf-8")) if d]
    return docs


def test_sigma_rules_are_wellformed():
    docs = sigma_docs()
    assert len(docs) >= 6
    ids = []
    for fname, d in docs:
        assert {"title", "id", "description"} <= set(d), fname
        assert str(uuid.UUID(d["id"])) == d["id"]
        ids.append(d["id"])
        assert ("detection" in d) != ("correlation" in d), fname
        if "detection" in d:
            assert "condition" in d["detection"] and "logsource" in d
        if d.get("level") in ("medium", "high", "critical"):
            assert any(re.fullmatch(r"attack\.t\d{4}", t) for t in d["tags"]), (fname, d["title"])
    assert len(ids) == len(set(ids))
    names = {d["name"] for _f, d in docs if "name" in d}
    for fname, d in docs:
        for ref in d.get("correlation", {}).get("rules", []):
            assert ref in names, (fname, ref)


def match_sigma(rule, ev):
    """Sigma 핵심 문법 일부(contains, startswith, lt, gte, 1 of selection_*)를 해석하는 최소 구현."""
    def field_ok(spec, ev):
        for key, expected in spec.items():
            name, _, mod = key.partition("|")
            val = ev.get(name)
            if val is None:
                return False
            exp = expected if isinstance(expected, list) else [expected]
            if mod == "contains":
                ok = any(str(e) in str(val) for e in exp)
            elif mod == "startswith":
                ok = any(str(val).startswith(str(e)) for e in exp)
            elif mod == "lt":
                ok = val < exp[0]
            elif mod == "gte":
                ok = val >= exp[0]
            else:
                ok = val in exp
            if not ok:
                return False
        return True

    det = rule["detection"]
    cond = det["condition"]
    sels = {k: v for k, v in det.items() if k != "condition"}
    if cond == "selection":
        return field_ok(sels["selection"], ev)
    assert cond == "1 of selection_*"
    return any(field_ok(v, ev) for k, v in sels.items() if k.startswith("selection_"))


def enrich(ev):
    """Filebeat의 script 프로세서가 하는 일: local_hour(KST 0~23) 추가."""
    d = datetime.fromisoformat(ev["ts"])
    return {**ev, "local_hour": (d.astimezone(timezone.utc).hour + 9) % 24}


def make_ev(ts, action, result="ok", detail=None, rows=1, user="agent01"):
    return {"ts": ts.astimezone(timezone.utc).isoformat(), "username": user, "action": action, "result": result,
            "rows": rows, "detail": detail, "ip": "10.0.0.5", "resource": None}


@pytest.mark.parametrize("fname,rule_id", [("defense_inactive_account_access.yml", "R3"),
                                          ("defense_offhours_data_access.yml", "R2")])
def test_sigma_matches_same_events_as_detector(fname, rule_id):
    """Sigma로 옮긴 규칙이 탐지 엔진의 규칙과 같은 이벤트를 잡는지 비교한다."""
    rule = yaml.safe_load((ROOT / "sigma" / fname).read_text(encoding="utf-8"))
    cases = []
    for h in (0, 2, 5, 6, 14, 23):
        cases.append(make_ev(datetime(2026, 11, 10, h, 30, tzinfo=KST), "customer.view"))
        cases.append(make_ev(datetime(2026, 11, 10, h, 30, tzinfo=KST), "customer.list", result="denied"))
        cases.append(make_ev(datetime(2026, 11, 10, h, 30, tzinfo=KST), "auth.login"))
    base = datetime(2026, 11, 10, 11, 0, tzinfo=KST)
    for action, result, detail in [("auth.login", "denied", "status=dormant"), ("auth.login", "denied", "status=locked"),
                                   ("auth.token", "denied", "inactive account"), ("auth.login", "failed", "username=x"),
                                   ("auth.login", "denied", "other"), ("auth.token", "denied", "invalid token")]:
        cases.append(make_ev(base, action, result, detail, rows=0))
    mismatches = []
    for ev in cases:
        sigma_hit = match_sigma(rule, enrich(ev))
        engine_hit = any(a.rule_id == rule_id for a in Detector().feed(ev))
        if sigma_hit != engine_hit:
            mismatches.append((ev["action"], ev["result"], ev["detail"], enrich(ev)["local_hour"], sigma_hit, engine_hit))
    assert not mismatches, mismatches


# ---------- R5~R7 Sigma (2차 보완) ----------
def sigma_by_title(title):
    for _f, d in sigma_docs():
        if d["title"].startswith(title):
            return d
    raise AssertionError(title)


def test_sigma_r7_matches_same_events_as_detector():
    """R7: 사전 차단 이벤트 하나로 매칭. 탐지 엔진의 R7과 같은 이벤트를 잡는지 비교한다."""
    rule = yaml.safe_load((ROOT / "sigma" / "defense_export_preblock.yml").read_text(encoding="utf-8"))
    t = datetime(2026, 11, 10, 15, 0, tzinfo=KST)
    cases = [
        make_ev(t, "customer.export", "blocked", "pre-block: 250건 조회 후 30분 이내 내보내기 시도", rows=0, user="admin01"),
        make_ev(t, "customer.export", "ok", None, rows=100, user="admin01"),
        make_ev(t, "customer.export", "denied", "reason missing", rows=0, user="admin01"),
        make_ev(t, "customer.export", "blocked", "other reason", rows=0, user="admin01"),
        make_ev(t, "customer.list", "blocked", "pre-block: x", rows=0, user="admin01"),
    ]
    got = [(match_sigma(rule, enrich(e)), any(a.rule_id == "R7" for a in Detector().feed(e))) for e in cases]
    assert [g[0] for g in got] == [g[1] for g in got] == [True, False, False, False, False]


def test_sigma_daily_thresholds_match_engine_for_50_row_pages():
    """R5·R6 근사 검증: 50건씩 조회하는 공격에서, Sigma의 횟수 기준이 엔진 발동 시점(몇 번째 조회)과 일치한다."""
    r5 = sigma_by_title("Daily Cumulative Customer Reads - Warning")["correlation"]
    r6 = sigma_by_title("Daily Cumulative Customer Reads - Block")["correlation"]
    assert r5["type"] == r6["type"] == "event_count" and r5["timespan"] == r6["timespan"] == "1d"
    assert r5["group-by"] == r6["group-by"] == ["username"]
    start = datetime(2026, 11, 10, 14, 0, tzinfo=KST)
    d = Detector()
    fired = {}
    for i in range(60):  # 분당 10건 속도(5분 간격 50건) -> R1은 걸리지 않는다
        for a in d.feed(make_ev(start + timedelta(minutes=5 * i), "customer.list", rows=50, user="insider01")):
            fired.setdefault(a.rule_id, i + 1)
    assert fired == {"R5": r5["condition"]["gte"], "R6": r6["condition"]["gte"]}  # 24번째, 40번째 조회


def test_sigma_daily_base_rule_selects_large_reads_only():
    base = next(d for _f, d in sigma_docs() if d.get("name") == "defense_customer_page_read_daily")
    t = datetime(2026, 11, 10, 14, 0, tzinfo=KST)
    assert match_sigma(base, enrich(make_ev(t, "customer.list", rows=50)))
    assert not match_sigma(base, enrich(make_ev(t, "customer.list", rows=49)))
    assert not match_sigma(base, enrich(make_ev(t, "customer.list", result="denied", rows=50)))


def test_sigma_levels_match_engine_severities():
    """Sigma level이 규칙 파일의 심각도와 일치하는지 확인한다."""
    cfg = load("rules/rules.yaml")
    sev = {r["id"]: r["severity"] for r in cfg["rules"]}
    pairs = {
        "Daily Cumulative Customer Reads - Warning": "R5",
        "Daily Cumulative Customer Reads - Block": "R6",
        "Customer Export Blocked After Bulk Read": "R7",
    }
    for title, rid in pairs.items():
        assert sigma_by_title(title)["level"] == sev[rid], (title, rid)


# ---------- R5~R7 저장된 검색 (2차 보완) ----------
def search_by_id(sid):
    return next(s for s in ks.SEARCHES if s[0] == sid)


def test_saved_searches_cover_all_rules_r1_to_r7():
    titles = " ".join(s[1] for s in ks.SEARCHES)
    for rid in ("R1", "R2", "R3", "R5", "R6", "R7"):
        assert rid in titles, rid
    ids = [s[0] for s in ks.SEARCHES]
    assert len(ids) == len(set(ids)), "저장된 검색 id가 중복됨"


def test_r5_r6_searches_query_alerts_by_rule_id():
    for sid, rid in (("defense-s-r5", "R5"), ("defense-s-r6", "R6")):
        _id, _title, view, query, cols = search_by_id(sid)
        assert view == "defense-alerts" and query == f'rule_id:"{rid}"'


def test_r7_and_warn_searches_query_audit_log():
    _id, _t, view, query, _c = search_by_id("defense-s-r7")
    assert view == "defense-audit" and 'result:"blocked"' in query and 'action:"customer.export"' in query
    _id, _t, view, query, _c = search_by_id("defense-s-warn")
    assert view == "defense-audit" and query == 'action:"response.warn"'


def test_search_values_match_what_the_app_actually_writes():
    """검색 조건의 값이 앱이 실제로 남기는 값과 일치하는지 소스에서 확인한다 (R7 결과값, 경고 이벤트 이름)."""
    main_src = (ROOT / "app" / "main.py").read_text(encoding="utf-8")
    resp_src = (ROOT / "app" / "response.py").read_text(encoding="utf-8")
    assert '"customer.export"' in main_src and '"blocked"' in main_src
    assert '"response.warn"' in resp_src
    rules = load("rules/rules.yaml")["rules"]
    assert {r["id"] for r in rules} >= {"R5", "R6", "R7"}


def test_dashboard_includes_every_saved_search_in_a_grid_without_overlap():
    dash = ks.dashboard_object()
    panels = json.loads(dash["attributes"]["panelsJSON"])
    assert len(panels) == len(ks.SEARCHES)
    seen = set()
    for p in panels:
        g = p["gridData"]
        cell = (g["x"], g["y"])
        assert cell not in seen, "패널 위치가 겹침"
        seen.add(cell)
        assert g["x"] + g["w"] <= 48
