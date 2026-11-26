"""민감정보(주민등록번호) 필드 암호화. DB 파일이 통째로 유출돼도 키 없이는 평문을 얻을 수 없게 한다.

저장 형식: "enc1:" + Fernet 토큰(AES-128-CBC + HMAC). 접두어가 없는 값은 예전 평문 데이터로 보고 그대로 읽는다.
복호화는 마스킹된 응답을 만들 때(앞 8자리)와 관리자의 마스킹 해제 시에만 일어난다.
"""
import base64
import hashlib

from cryptography.fernet import Fernet, InvalidToken

from app import config

PREFIX = "enc1:"


def _fernet():
    key = config.DATA_KEY
    if not key:  # 모의 환경 전용 기본 키. 실제 서비스는 비밀관리 서비스(KMS 등)에서 주입해야 한다.
        key = base64.urlsafe_b64encode(hashlib.sha256(b"defense-follow-demo-data-key").digest())
    return Fernet(key)


def encrypt(plain: str) -> str:
    return PREFIX + _fernet().encrypt(plain.encode()).decode()


def decrypt(stored: str) -> str:
    """암호문이면 복호화하고, 평문(구 데이터)이면 그대로 돌려준다. 키가 틀리면 빈 문자열(마스킹은 실패해도 노출하지 않음)."""
    if not stored.startswith(PREFIX):
        return stored
    try:
        return _fernet().decrypt(stored[len(PREFIX):].encode()).decode()
    except InvalidToken:
        return ""
