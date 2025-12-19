from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Tuple

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

from . import utils

BLOCK_SIZE = 16


def _pad(data: bytes) -> bytes:
    pad_len = BLOCK_SIZE - (len(data) % BLOCK_SIZE)
    return data + bytes([pad_len] * pad_len)


def _unpad(data: bytes) -> bytes:
    pad_len = data[-1]
    if pad_len == 0 or pad_len > BLOCK_SIZE:
        raise ValueError("Invalid padding")
    if data[-pad_len:] != bytes([pad_len] * pad_len):
        raise ValueError("Invalid padding bytes")
    return data[:-pad_len]


@dataclass
class EncryptedPayload:
    ciphertext: bytes
    iv: bytes
    hmac_tag: bytes

    def serialize(self) -> str:
        payload = {
            "ciphertext": utils.encode_bytes(self.ciphertext),
            "iv": utils.encode_bytes(self.iv),
            "hmac": utils.encode_bytes(self.hmac_tag),
        }
        return json.dumps(payload)

    @classmethod
    def deserialize(cls, payload: str) -> "EncryptedPayload":
        data = json.loads(payload)
        return cls(
            ciphertext=utils.decode_bytes(data["ciphertext"]),
            iv=utils.decode_bytes(data["iv"]),
            hmac_tag=utils.decode_bytes(data["hmac"]),
        )


def encrypt(shared_key: bytes, plaintext: str) -> EncryptedPayload:
    iv = get_random_bytes(BLOCK_SIZE)
    cipher = AES.new(shared_key, AES.MODE_CBC, iv)
    padded = _pad(plaintext.encode("utf-8"))
    ciphertext = cipher.encrypt(padded)
    tag = utils.generate_hmac(shared_key, iv + ciphertext)
    return EncryptedPayload(ciphertext=ciphertext, iv=iv, hmac_tag=tag)


def decrypt(shared_key: bytes, payload: EncryptedPayload) -> str:
    if not utils.verify_hmac(shared_key, payload.iv + payload.ciphertext, payload.hmac_tag):
        raise ValueError("HMAC verification failed")
    cipher = AES.new(shared_key, AES.MODE_CBC, payload.iv)
    padded = cipher.decrypt(payload.ciphertext)
    plaintext = _unpad(padded)
    return plaintext.decode("utf-8")

