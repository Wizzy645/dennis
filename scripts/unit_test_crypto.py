from __future__ import annotations

import secrets

from apps.common.crypto_utils import aes256gcm_decrypt, aes256gcm_encrypt
from apps.key_management_server.crypto import DEK_BYTES_LEN, generate_rsa_keypair, rsa_decrypt_dek, rsa_encrypt_dek


def main() -> None:
    # AES-256-GCM roundtrip
    dek = secrets.token_bytes(DEK_BYTES_LEN)
    iv = secrets.token_bytes(12)  # 96-bit nonce
    aad = b"emr-encryption"
    plaintext = b"patient-record-payload"

    ciphertext, auth_tag = aes256gcm_encrypt(plaintext, dek=dek, iv=iv, aad=aad)
    recovered = aes256gcm_decrypt(ciphertext, auth_tag, dek=dek, iv=iv, aad=aad)
    assert recovered == plaintext, "AES-256-GCM decrypt/encrypt mismatch"

    # RSA-OAEP roundtrip for DEK wrapping/unwrapping
    public_pem, private_pem = generate_rsa_keypair()
    encrypted_dek = rsa_encrypt_dek(dek, public_key_pem=public_pem)
    unwrapped_dek = rsa_decrypt_dek(encrypted_dek, private_key_pem=private_pem)
    assert unwrapped_dek == dek, "RSA-OAEP decrypt/encrypt mismatch"

    print("unit_test_crypto: PASS")


if __name__ == "__main__":
    main()

