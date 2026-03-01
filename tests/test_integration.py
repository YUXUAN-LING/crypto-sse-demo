from __future__ import annotations

import os
import secrets
import uuid
from pathlib import Path

from fastapi.testclient import TestClient

from common.crypto import derive_subkeys_hkdf, encrypt_aes_gcm, token_for_keyword
from common.utils import b64_encode, b64url_encode


def test_server_upload_search_fetch(tmp_path, monkeypatch):
    # Set storage dir before importing app
    monkeypatch.setenv("SSE_DATA_DIR", str(tmp_path / "data"))

    from server.app import create_app  # import after env set

    app = create_app()
    client = TestClient(app)

    # health
    r = client.post("/health")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"

    # prepare crypto
    k_master = secrets.token_bytes(32)
    keys = derive_subkeys_hkdf(k_master)

    # create doc
    doc_id = str(uuid.uuid4())
    pt = b"hello searchable encryption"
    nonce, ct = encrypt_aes_gcm(keys.k_f, pt, aad=doc_id.encode("utf-8"))

    kw = "searchable"
    token = b64url_encode(token_for_keyword(keys.k_w, kw))

    payload = {
        "doc_id": doc_id,
        "nonce_b64": b64_encode(nonce),
        "ct_b64": b64_encode(ct),
        "meta": {"filename": "x.txt"},
        "tokens": [token],
    }

    r = client.post("/upload_doc", json=payload)
    assert r.status_code == 200

    # search
    r = client.post("/search", json={"token_b64url": token})
    assert r.status_code == 200
    data = r.json()
    assert doc_id in data["doc_ids"]
    assert len(data["docs"]) == 1
    assert data["docs"][0]["doc_id"] == doc_id

    # fetch
    r = client.get(f"/fetch/{doc_id}")
    assert r.status_code == 200
    f = r.json()
    assert f["doc_id"] == doc_id
