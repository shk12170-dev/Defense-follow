import pytest


@pytest.fixture(autouse=True)
def _defense_off_by_default(monkeypatch):
    """기존 테스트는 탐지·자동 차단 없이 API 동작만 검증한다. 4일차 테스트가 필요할 때 켠다."""
    monkeypatch.setenv("DEFENSE_MODE", "off")
    from app import response
    response.reset()
    yield
    response.reset()
