from crypto import encryption, hashing, key_exchange
from crypto.encryption import EncryptedPayload
from crypto.utils import generate_hmac, verify_hmac


def test_aes_encrypt_decrypt_roundtrip():
    key_pair_a = key_exchange.generate_key_pair()
    key_pair_b = key_exchange.generate_key_pair()
    shared_a = key_exchange.compute_shared_key(key_pair_a.private_key, key_pair_b.public_key)
    shared_b = key_exchange.compute_shared_key(key_pair_b.private_key, key_pair_a.public_key)

    assert shared_a == shared_b

    plaintext = "Confidential Message"
    payload = encryption.encrypt(shared_a, plaintext)
    decrypted = encryption.decrypt(shared_b, payload)
    assert decrypted == plaintext


def test_hmac_generation_and_validation():
    key = b"A" * 32
    data = b"hello world"
    tag = generate_hmac(key, data)
    assert verify_hmac(key, data, tag)
    assert not verify_hmac(key, data + b"!", tag)


def test_bcrypt_hashing_roundtrip():
    password = "ComplexPass!234"
    hashed = hashing.hash_password(password)
    assert hashing.verify_password(password, hashed)
    assert not hashing.verify_password("wrong", hashed)

