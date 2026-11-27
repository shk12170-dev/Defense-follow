import pytest


@pytest.fixture(autouse=True)
def _isolate_defense_env(monkeypatch, tmp_path):
    """기존 테스트는 탐지·자동 차단 없이 API 동작만 검증한다. 4일차 이후 테스트가 필요할 때 켠다.
    경보 로그 파일이 저장소의 logs/ 에 쓰이지 않도록 임시 경로로 돌린다."""
    monkeypatch.setenv("DEFENSE_MODE", "off")
    monkeypatch.setenv("DEFENSE_ALERT_LOG", str(tmp_path / "alerts.jsonl"))
    from app import config, response
    monkeypatch.setattr(config, "ALERT_LOG_PATH", tmp_path / "alerts.jsonl")
    response.reset()
    # 유형별·단기 쿼터와 재인증 후 축소는 기존 테스트의 흐름(대량 조회로 R1 발동 등)을 막으므로 기본으로 끄고,
    # 해당 기능을 검증하는 테스트만 켠다(tests/test_day19_quota_profiles.py). 24시간·7일 합계 쿼터는 그대로 둔다.
    from app import quota
    from app.detection import load_rules
    cfg = load_rules()
    cfg["quota"] = {k: v for k, v in cfg["quota"].items() if k not in ("profiles", "stepup_penalty", "profile")}
    monkeypatch.setattr(quota, "_rules", cfg)
    yield
    response.reset()
