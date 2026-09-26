"""HMAC-SHA-256 and AES-256 key wrap (RFC 3394) for DNP3 SAv5."""

from __future__ import annotations

import hashlib
import hmac
import os

from cryptography.hazmat.primitives.keywrap import InvalidUnwrap, aes_key_unwrap, aes_key_wrap

MAC_LEN = 16
HMAC_SHA256_LEN = 32
SESSION_KEY_LEN = 32
UPDATE_KEY_LEN = 32
CHALLENGE_LEN = 16
UK_CHALLENGE_LEN = 32


def random_bytes(n: int) -> bytes:
    return os.urandom(n)


def same_bytes(a: bytes, b: bytes) -> bool:
    if len(a) != len(b):
        return False
    diff = 0
    for x, y in zip(a, b):
        diff |= x ^ y
    return diff == 0


def bytes_to_hex(data: bytes) -> str:
    return data.hex()


def hex_to_bytes(text: str, length: int | None = None) -> bytes | None:
    cleaned = "".join(ch for ch in text if ch in "0123456789abcdefABCDEF")
    if not cleaned or len(cleaned) % 2:
        return None
    if length is not None and len(cleaned) != length * 2:
        return None
    return bytes.fromhex(cleaned)


def session_mac(key: bytes, message: bytes, length: int, sha1: bool) -> bytes:
    digest = hashlib.sha1 if sha1 else hashlib.sha256
    return hmac.new(key, message, digest).digest()[:length]


def aes_wrap(kek: bytes, plaintext: bytes) -> bytes:
    if len(kek) not in (16, 32):
        raise ValueError("Key wrap wants a 16-octet or 32-octet key")
    if len(plaintext) < 16 or len(plaintext) % 8:
        raise ValueError("Key-wrap plaintext must be a multiple of 8, at least 16")
    return aes_key_wrap(kek, plaintext)


def aes_unwrap(kek: bytes, wrapped: bytes) -> bytes | None:
    if len(kek) not in (16, 32) or len(wrapped) < 24 or len(wrapped) % 8:
        return None
    try:
        return aes_key_unwrap(kek, wrapped)
    except InvalidUnwrap:
        return None


def hmac_sha256(key: bytes, message: bytes, length: int = MAC_LEN) -> bytes:
    return session_mac(key, message, length, False)


def aes256_wrap(kek: bytes, plaintext: bytes) -> bytes:
    if len(kek) != UPDATE_KEY_LEN:
        raise ValueError("AES-256 key wrap wants a 32-octet key")
    return aes_wrap(kek, plaintext)


def aes256_unwrap(kek: bytes, wrapped: bytes) -> bytes | None:
    if len(kek) != UPDATE_KEY_LEN:
        return None
    return aes_unwrap(kek, wrapped)
