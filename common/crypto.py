from __future__ import annotations

import secrets
from dataclasses import dataclass
from typing import Tuple

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt


HKDF_INFO = b"sse-demo-hkdf-info-v1"
HKDF_SALT = b"sse-demo-hkdf-salt-v1"
CONFIG_CHECK_LABEL = b"SSE_CONFIG_CHECK_V1"


@dataclass(frozen=True)
class DerivedKeys:
    """Separated keys derived from K_master."""
    k_w: bytes  # keyword/token HMAC key
    k_f: bytes  # file/document encryption key (AES-GCM)


def derive_master_key_scrypt(
    passphrase: bytes,
    salt: bytes,
    n: int = 2**14,
    r: int = 8,
    p: int = 1,
    length: int = 32,
) -> bytes:
    """
    Derive K_master from passphrase using scrypt.
    Parameters follow cryptography's Scrypt interface.
    """
    kdf = Scrypt(salt=salt, length=length, n=n, r=r, p=p)
    return kdf.derive(passphrase)


def derive_subkeys_hkdf(k_master: bytes) -> DerivedKeys:
    """
    Derive (k_w, k_f) from K_master using HKDF-SHA256.
    We derive 64 bytes total and split into two 32-byte subkeys.
    """
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=64,
        salt=HKDF_SALT,
        info=HKDF_INFO,
    )
    okm = hkdf.derive(k_master)
    return DerivedKeys(k_w=okm[:32], k_f=okm[32:])


def hmac_sha256(key: bytes, msg: bytes) -> bytes:
    h = hmac.HMAC(key, hashes.SHA256())
    h.update(msg)
    return h.finalize()


def hmac_verify_sha256(key: bytes, msg: bytes, signature: bytes) -> bool:
    h = hmac.HMAC(key, hashes.SHA256())
    h.update(msg)
    try:
        h.verify(signature)
        return True
    except InvalidSignature:
        return False


def token_for_keyword(k_w: bytes, keyword_normalized: str) -> bytes:
    """
    Generate deterministic SSE token for normalized keyword.
    token = HMAC_SHA256(K_w, keyword_normalized)
    """
    return hmac_sha256(k_w, keyword_normalized.encode("utf-8"))


def encrypt_aes_gcm(k_f: bytes, plaintext: bytes, aad: bytes) -> Tuple[bytes, bytes]:
    """
    Encrypt using AES-GCM with random 12-byte nonce.
    WARNING: Nonce must never repeat with the same key. We use random nonce.
    """
    nonce = secrets.token_bytes(12)
    aesgcm = AESGCM(k_f)
    ct = aesgcm.encrypt(nonce, plaintext, aad)
    return nonce, ct


def decrypt_aes_gcm(k_f: bytes, nonce: bytes, ciphertext: bytes, aad: bytes) -> bytes:
    """
    Decrypt AES-GCM. Raises InvalidTag if auth fails (wrong key/nonce/aad or tampered ct).
    """
    aesgcm = AESGCM(k_f)
    return aesgcm.decrypt(nonce, ciphertext, aad)


def make_config_check(k_master: bytes) -> bytes:
    """
    A deterministic check value stored in config, to validate passphrase later.
    """
    return hmac_sha256(k_master, CONFIG_CHECK_LABEL)
