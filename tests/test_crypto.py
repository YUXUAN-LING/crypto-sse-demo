from __future__ import annotations

import secrets

import pytest
from cryptography.exceptions import InvalidTag

from common.crypto import (
    decrypt_aes_gcm,
    derive_master_key_scrypt,
    derive_subkeys_hkdf,
    encrypt_aes_gcm,
    token_for_keyword,
)
from common.utils import b64url_decode, b64url_encode


def test_token_deterministic():
    k_master = secrets.token_bytes(32)
    keys = derive_subkeys_hkdf(k_master)
    t1 = token_for_keyword(keys.k_w, "cryptography")
    t2 = token_for_keyword(keys.k_w, "cryptography")
    assert t1 == t2
    assert b64url_decode(b64url_encode(t1)) == t1


def test_aesgcm_roundtrip_and_aad_binding():
    k_master = secrets.token_bytes(32)
    keys = derive_subkeys_hkdf(k_master)

    doc_id = "doc-123"
    aad = doc_id.encode("utf-8")
    pt = b"hello world"

    nonce, ct = encrypt_aes_gcm(keys.k_f, pt, aad=aad)
    out = decrypt_aes_gcm(keys.k_f, nonce, ct, aad=aad)
    assert out == pt

    with pytest.raises(InvalidTag):
        _ = decrypt_aes_gcm(keys.k_f, nonce, ct, aad=b"wrong-aad")


def test_scrypt_derivation_consistent():
    salt = secrets.token_bytes(16)
    passphrase = b"test-pass"
    k1 = derive_master_key_scrypt(passphrase, salt=salt)
    k2 = derive_master_key_scrypt(passphrase, salt=salt)
    assert k1 == k2
