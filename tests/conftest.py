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
    yield
    response.reset()
