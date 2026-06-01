from __future__ import annotations

from dataclasses import dataclass

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

DEK_BYTES_LEN = 32  # 256-bit DEK


@dataclass(frozen=True)
class RsaMasterKey:
    key_version: int
    public_key_pem: str
    private_key_pem: str


def generate_rsa_keypair() -> tuple[str, str]:
    """
    Generates a per-tenant RSA keypair to protect DEKs.
    """
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("ascii")

    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")

    return public_pem, private_pem


def rsa_encrypt_dek(dek: bytes, *, public_key_pem: str) -> bytes:
    if len(dek) != DEK_BYTES_LEN:
        raise ValueError("DEK must be exactly 32 bytes (256-bit)")

    public_key = serialization.load_pem_public_key(public_key_pem.encode("ascii"))
    if not hasattr(public_key, "encrypt"):
        raise ValueError("Invalid RSA public key")

    return public_key.encrypt(
        dek,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


def rsa_decrypt_dek(encrypted_dek: bytes, *, private_key_pem: str) -> bytes:
    private_key = serialization.load_pem_private_key(private_key_pem.encode("ascii"), password=None)
    if not hasattr(private_key, "decrypt"):
        raise ValueError("Invalid RSA private key")

    dek = private_key.decrypt(
        encrypted_dek,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    if len(dek) != DEK_BYTES_LEN:
        raise ValueError("Decrypted DEK had unexpected length")
    return dek

