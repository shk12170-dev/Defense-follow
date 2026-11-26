"""TOTP(RFC 6238) 최소 구현 — 단계적 재인증(step-up)용 모의 MFA. 표준 라이브러리만 사용한다."""
import base64
import hashlib
import hmac
import struct
import time

STEP = 30
DIGITS = 6


def new_secret(seed_text):
    """모의 환경용 결정적 비밀값(base32). 실제 서비스는 무작위 비밀값을 사용자별로 발급해야 한다."""
    return base64.b32encode(hashlib.sha256(seed_text.encode()).digest()[:10]).decode()


def code_for(secret, at=None):
    key = base64.b32decode(secret)
    counter = int((time.time() if at is None else at) // STEP)
    digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    off = digest[-1] & 0x0F
    num = (struct.unpack(">I", digest[off:off + 4])[0] & 0x7FFFFFFF) % (10 ** DIGITS)
    return f"{num:0{DIGITS}d}"


def verify(secret, code, at=None, window=1):
    """현재 구간과 앞뒤 window 구간의 코드를 허용한다(시계 오차 대응)."""
    if not code or not code.isdigit() or len(code) != DIGITS:
        return False
    now = time.time() if at is None else at
    return any(hmac.compare_digest(code_for(secret, now + i * STEP), code) for i in range(-window, window + 1))
