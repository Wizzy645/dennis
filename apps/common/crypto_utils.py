from __future__ import annotations

import base64
from typing import Final

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


AES_256_KEY_BYTES: Final[int] = 32
GCM_NONCE_BYTES: Final[int] = 12
GCM_TAG_BYTES: Final[int] = 16


def b64encode_bytes(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def b64decode_bytes(data_b64: str) -> bytes:
    return base64.b64decode(data_b64.encode("ascii"))


def aes256gcm_encrypt(plaintext: bytes, *, dek: bytes, iv: bytes, aad: bytes = b"") -> tuple[bytes, bytes]:
    """
    Envelope encryption payload step (AES-256-GCM).

    Returns (ciphertext, auth_tag).
    """
    if len(dek) != AES_256_KEY_BYTES:
        raise ValueError("DEK must be 256-bit (32 bytes)")
    if len(iv) != GCM_NONCE_BYTES:
        raise ValueError("IV must be 96-bit (12 bytes)")

    aesgcm = AESGCM(dek)
    # cryptography returns ciphertext || tag
    ct_and_tag = aesgcm.encrypt(iv, plaintext, aad)
    ciphertext = ct_and_tag[:-GCM_TAG_BYTES]
    auth_tag = ct_and_tag[-GCM_TAG_BYTES:]
    return ciphertext, auth_tag


def aes256gcm_decrypt(ciphertext: bytes, auth_tag: bytes, *, dek: bytes, iv: bytes, aad: bytes = b"") -> bytes:
    if len(dek) != AES_256_KEY_BYTES:
        raise ValueError("DEK must be 256-bit (32 bytes)")
    if len(iv) != GCM_NONCE_BYTES:
        raise ValueError("IV must be 96-bit (12 bytes)")
    if len(auth_tag) != GCM_TAG_BYTES:
        raise ValueError("auth_tag must be 128-bit (16 bytes)")

    aesgcm = AESGCM(dek)
    ct_and_tag = ciphertext + auth_tag
    return aesgcm.decrypt(iv, ct_and_tag, aad)


def best_effort_wipe_bytearray(buf: bytearray) -> None:
    """
    Best-effort scrubbing.
    Python/GC cannot guarantee memory is never copied, but this overwrites the buffer in-place.
    """
    for i in range(len(buf)):
        buf[i] = 0

