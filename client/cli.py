from __future__ import annotations

import logging
import sys
import uuid
from pathlib import Path
from typing import Optional

import typer

from client.api import SSEServerClient
from client.config import (
    ClientConfig,
    init_keyfile_config,
    init_passphrase_config,
    load_keys_from_config,
)
from client.indexer import extract_keywords_from_file, iter_txt_files, normalize_keyword
from common.crypto import decrypt_aes_gcm, encrypt_aes_gcm, token_for_keyword
from common.utils import b64_decode, b64_encode, b64url_encode, utc_now_iso

app = typer.Typer(
    name="sse-demo",
    add_completion=False,
    help="SSE Demo CLI: upload encrypted documents and search via encrypted tokens.",
)

logger = logging.getLogger("sse.client")
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")


def _load_config(config_path: Optional[Path]) -> ClientConfig:
    return ClientConfig.load(config_path)


def _get_server(cfg: ClientConfig) -> SSEServerClient:
    return SSEServerClient(base_url=cfg.server_url)


def _maybe_prompt_passphrase(cfg: ClientConfig) -> Optional[str]:
    if cfg.mode == "passphrase":
        return typer.prompt("Passphrase", hide_input=True)
    return None


@app.command()
def init(
    mode: str = typer.Option("passphrase", help="passphrase or keyfile"),
    server_url: str = typer.Option("http://127.0.0.1:8000", help="Server base URL"),
    config_path: Optional[Path] = typer.Option(None, help="Path to config.json (default: client/config.json)"),
):
    """
    Initialize client configuration.
    - passphrase mode: derive K_master via scrypt; store salt+params+check in config.json
    - keyfile mode: generate random K_master and store in a local keyfile
    """
    mode = mode.strip().lower()
    if mode not in ("passphrase", "keyfile"):
        raise typer.BadParameter("mode must be 'passphrase' or 'keyfile'")

    config_path = config_path or ClientConfig.default_path()

    if mode == "passphrase":
        pass1 = typer.prompt("Set a passphrase", hide_input=True, confirmation_prompt=True)
        import secrets

        salt = secrets.token_bytes(16)
        cfg = init_passphrase_config(server_url=server_url, passphrase=pass1, salt=salt)
        cfg.save(config_path)
        typer.echo(f"[ok] Wrote config: {config_path}")
        typer.echo("Mode: passphrase (scrypt -> K_master)")
        return

    # keyfile mode
    keyfile_path = config_path.parent / ".sse_key"
    import secrets

    k_master = secrets.token_bytes(32)
    cfg = init_keyfile_config(server_url=server_url, keyfile_path=keyfile_path, k_master=k_master)
    cfg.save(config_path)
    typer.echo(f"[ok] Wrote config: {config_path}")
    typer.echo(f"[ok] Wrote keyfile: {keyfile_path}")
    typer.echo("Mode: keyfile (random K_master)")
    typer.echo("NOTE: keep the keyfile secret. Do NOT commit it to git.")


@app.command()
def upload(
    dir: Path = typer.Option(..., exists=True, file_okay=False, dir_okay=True, help="Folder containing .txt files"),
    config_path: Optional[Path] = typer.Option(None, help="Path to config.json (default: client/config.json)"),
):
    """
    Upload all .txt documents under a directory:
    - extract keywords
    - encrypt document (AES-GCM)
    - compute tokens (HMAC)
    - send to server /upload_doc
    """
    cfg = _load_config(config_path)
    server = _get_server(cfg)

    passphrase = _maybe_prompt_passphrase(cfg)
    _, keys = load_keys_from_config(cfg, passphrase=passphrase)

    # Health check
    try:
        server.health()
    except Exception as e:
        typer.echo(f"[error] server health check failed: {e}")
        raise typer.Exit(code=1)

    files = list(iter_txt_files(dir))
    if not files:
        typer.echo("[warn] no .txt files found")
        raise typer.Exit(code=0)

    typer.echo(f"[info] found {len(files)} .txt files under {dir}")

    for fp in files:
        doc_id = str(uuid.uuid4())
        keywords = extract_keywords_from_file(fp)
        tokens = [b64url_encode(token_for_keyword(keys.k_w, kw)) for kw in sorted(keywords)]

        plaintext = fp.read_bytes()
        aad = doc_id.encode("utf-8")
        nonce, ct = encrypt_aes_gcm(keys.k_f, plaintext, aad=aad)

        payload = {
            "doc_id": doc_id,
            "nonce_b64": b64_encode(nonce),
            "ct_b64": b64_encode(ct),
            "meta": {
                "filename": fp.name,
                "uploaded_at": utc_now_iso(),
                "keywords_count": len(keywords),
            },
            "tokens": tokens,
        }

        resp = server.upload_doc(payload)
        typer.echo(
            f"[ok] uploaded {fp.name} -> doc_id={resp.get('doc_id')} "
            f"keywords={len(keywords)} ct_len={len(payload['ct_b64'])}"
        )


@app.command()
def search(
    kw: str = typer.Option(..., help="Keyword to search"),
    config_path: Optional[Path] = typer.Option(None, help="Path to config.json (default: client/config.json)"),
):
    """
    Search by a single keyword:
    - normalize keyword
    - token = HMAC(K_w, normalize(kw))
    - server /search(token) -> encrypted docs
    - client decrypt and show snippet
    """
    cfg = _load_config(config_path)
    server = _get_server(cfg)
    passphrase = _maybe_prompt_passphrase(cfg)
    _, keys = load_keys_from_config(cfg, passphrase=passphrase)

    kw_norm = normalize_keyword(kw)
    if not kw_norm:
        typer.echo("[error] keyword is empty after normalization")
        raise typer.Exit(code=1)

    tok = b64url_encode(token_for_keyword(keys.k_w, kw_norm))
    typer.echo(f"[info] keyword(normalized) = '{kw_norm}'")
    typer.echo(f"[info] token(base64url)    = {tok}")

    resp = server.search(tok)
    docs = resp.get("docs", []) or []
    if not docs:
        typer.echo("[info] no hits")
        raise typer.Exit(code=0)

    typer.echo(f"[ok] hits: {len(docs)}")
    for d in docs:
        doc_id = d["doc_id"]
        nonce = b64_decode(d["nonce_b64"])
        ct = b64_decode(d["ct_b64"])
        meta = d.get("meta", {}) or {}

        try:
            pt = decrypt_aes_gcm(keys.k_f, nonce, ct, aad=doc_id.encode("utf-8"))
        except Exception as e:
            typer.echo(f"[error] decrypt failed for doc_id={doc_id}: {e}")
            continue

        text = pt.decode("utf-8", errors="ignore").replace("\r\n", "\n")
        snippet = text[:200].replace("\n", "\\n")
        typer.echo(f"- doc_id={doc_id} filename={meta.get('filename')} snippet='{snippet}...'")

    # Optional server stats
    try:
        st = server.stats()
        typer.echo(f"[info] server stats: docs={st.get('doc_count')} tokens={st.get('token_count')}")
    except Exception:
        pass


@app.command()
def show(
    doc_id: str = typer.Option(..., help="doc_id to fetch & decrypt"),
    config_path: Optional[Path] = typer.Option(None, help="Path to config.json (default: client/config.json)"),
):
    cfg = _load_config(config_path)
    server = _get_server(cfg)
    passphrase = _maybe_prompt_passphrase(cfg)
    _, keys = load_keys_from_config(cfg, passphrase=passphrase)

    d = server.fetch(doc_id)
    nonce = b64_decode(d["nonce_b64"])
    ct = b64_decode(d["ct_b64"])
    pt = decrypt_aes_gcm(keys.k_f, nonce, ct, aad=doc_id.encode("utf-8"))

    typer.echo(f"[ok] doc_id={doc_id} filename={d.get('meta', {}).get('filename')}")
    typer.echo(pt.decode("utf-8", errors="ignore"))


if __name__ == "__main__":
    app()
