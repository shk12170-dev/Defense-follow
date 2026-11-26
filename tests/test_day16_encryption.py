"""민감정보 암호화 저장 검증."""
import importlib
import re

import pytest
from fastapi.testclient import TestClient

PW = "Demo#2026pw"


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("DEFENSE_DB", str(tmp_path / "t.db"))
    monkeypatch.setenv("DEFENSE_AUDIT_LOG", str(tmp_path / "audit.jsonl"))
    monkeypatch.setenv("DEFENSE_MODE", "off")
    from app import config
    importlib.reload(config)
    from app import audit
    audit._last_hash.clear()
    from scripts import seed
    importlib.reload(seed)
    seed.main(n_customers=200)
    from app import main
    with TestClient(main.app) as c:
        yield c


def hdr(c, user="admin01"):
    return {"Authorization": "Bearer " + c.post("/auth/login", json={"username": user, "password": PW}).json()["access_token"]}


def raw_rrns():
    from app import db as dbm
    conn = dbm.connect()
    r = [x[0] for x in conn.execute("SELECT rrn FROM customers")]
    conn.close()
    return r


def test_rrn_is_encrypted_at_rest(client):
    vals = raw_rrns()
    assert vals and all(v.startswith("enc1:") for v in vals)
    assert not any(re.search(r"\d{6}-\d{7}", v) for v in vals)  # DB 파일에 주민번호 평문이 없다


def test_masked_output_format_unchanged(client):
    it = client.get("/customers?page=1&size=5", headers=hdr(client)).json()["items"][0]
    assert re.fullmatch(r"\d{6}-\d\*{6}", it["rrn"])


def test_unmask_decrypts_to_plain_rrn(client):
    r = client.get("/customers/1?unmask=true&reason=본인 확인 업무", headers=hdr(client)).json()
    assert re.fullmatch(r"\d{6}-\d{7}", r["rrn"])


def test_legacy_plaintext_rows_still_readable(client):
    from app import db as dbm
    conn = dbm.connect()
    conn.execute("UPDATE customers SET rrn='900101-1234567' WHERE id=2")
    conn.commit()
    conn.close()
    assert client.get("/customers/2?unmask=true&reason=구 데이터 확인", headers=hdr(client)).json()["rrn"] == "900101-1234567"


def test_wrong_key_fails_closed(client, monkeypatch):
    from cryptography.fernet import Fernet
    from app import config
    monkeypatch.setattr(config, "DATA_KEY", Fernet.generate_key().decode())
    assert client.get("/customers/1?unmask=true&reason=키 불일치 확인", headers=hdr(client)).json()["rrn"] == ""
    assert client.get("/customers/1", headers=hdr(client)).json()["rrn"] == "******"  # 마스킹도 평문을 만들지 않는다


def test_crypto_roundtrip_and_ciphertext_differs():
    from app import crypto
    a, b = crypto.encrypt("900101-1234567"), crypto.encrypt("900101-1234567")
    assert a != b and crypto.decrypt(a) == crypto.decrypt(b) == "900101-1234567"
