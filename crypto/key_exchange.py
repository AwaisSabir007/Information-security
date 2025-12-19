from __future__ import annotations

import secrets
from dataclasses import dataclass

from .utils import hkdf_sha256

# 2048-bit MODP Group from RFC 3526
P = int(
    """
    FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1
    29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD
    EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245
    E485B576 625E7EC6 F44C42E9 A63A3620 FFFFFFFF FFFFFFFF
    """.replace(" ", "").replace("\n", ""),
    16,
)
G = 2


@dataclass
class KeyPair:
    private_key: int
    public_key: int


def generate_private_key() -> int:
    return secrets.randbelow(P - 2) + 2


def generate_key_pair() -> KeyPair:
    priv = generate_private_key()
    pub = pow(G, priv, P)
    return KeyPair(private_key=priv, public_key=pub)


def compute_shared_key(private_key: int, peer_public_key: int) -> bytes:
    shared_secret = pow(peer_public_key, private_key, P)
    return hkdf_sha256(shared_secret)

