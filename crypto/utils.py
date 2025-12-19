from __future__ import annotations

import base64
import hashlib
import hmac
from typing import Tuple


def sha256_digest(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def hkdf_sha256(shared_secret: int, info: bytes = b"secure-chat") -> bytes:
    """
    Derive a 32-byte key from the shared secret using HKDF-style extraction.
    """
    length = max(1, (shared_secret.bit_length() + 7) // 8)
    secret_bytes = shared_secret.to_bytes(length, byteorder="big", signed=False)
    prk = hmac.new(b"secure-chat-hkdf", secret_bytes, hashlib.sha256).digest()
    okm = hmac.new(prk, info + b"\x01", hashlib.sha256).digest()
    return okm


def encode_bytes(data: bytes) -> str:
    return base64.b64encode(data).decode("utf-8")


def decode_bytes(data: str) -> bytes:
    return base64.b64decode(data.encode("utf-8"))


def generate_hmac(key: bytes, data: bytes) -> bytes:
    return hmac.new(key, data, hashlib.sha256).digest()


def verify_hmac(key: bytes, data: bytes, expected: bytes) -> bool:
    actual = generate_hmac(key, data)
    return hmac.compare_digest(actual, expected)

