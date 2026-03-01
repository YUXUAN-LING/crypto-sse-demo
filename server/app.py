from __future__ import annotations

import logging
from typing import List

from fastapi import FastAPI, HTTPException

from server.models import (
    EncryptedDocBundle,
    FetchDocResponse,
    HealthResponse,
    SearchRequest,
    SearchResponse,
    StatsResponse,
    UploadDocRequest,
    UploadDocResponse,
)
from server.settings import get_settings
from server.storage import JsonStorage, StoredDoc

logger = logging.getLogger("sse.server")
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")


def create_app() -> FastAPI:
    settings = get_settings()
    storage = JsonStorage(settings.state_path)

    app = FastAPI(title="SSE Demo Server", version="1.0.0")

    @app.post("/health", response_model=HealthResponse)
    async def health() -> HealthResponse:
        return HealthResponse(status="ok")

    @app.post("/upload_doc", response_model=UploadDocResponse)
    async def upload_doc(req: UploadDocRequest) -> UploadDocResponse:
        if storage.doc_exists(req.doc_id):
            raise HTTPException(status_code=409, detail=f"doc_id already exists: {req.doc_id}")

        doc = StoredDoc(
            doc_id=req.doc_id,
            nonce_b64=req.nonce_b64,
            ct_b64=req.ct_b64,
            meta=req.meta,
        )
        try:
            storage.add_doc(doc, req.tokens)
        except ValueError as e:
            raise HTTPException(status_code=409, detail=str(e)) from e

        logger.info(
            "upload_doc doc_id=%s tokens=%d ct_len=%d",
            req.doc_id,
            len(req.tokens),
            len(req.ct_b64),
        )
        return UploadDocResponse(status="ok", doc_id=req.doc_id)

    @app.post("/search", response_model=SearchResponse)
    async def search(req: SearchRequest) -> SearchResponse:
        doc_ids = storage.search(req.token_b64url)
        docs: List[EncryptedDocBundle] = []
        for doc_id in doc_ids:
            rec = storage.get_doc(doc_id)
            if rec is None:
                continue
            docs.append(
                EncryptedDocBundle(
                    doc_id=rec.doc_id,
                    nonce_b64=rec.nonce_b64,
                    ct_b64=rec.ct_b64,
                    meta=rec.meta,
                )
            )

        logger.info("search token=%s hits=%d", req.token_b64url, len(doc_ids))
        return SearchResponse(doc_ids=doc_ids, docs=docs)

    @app.get("/fetch/{doc_id}", response_model=FetchDocResponse)
    async def fetch(doc_id: str) -> FetchDocResponse:
        rec = storage.get_doc(doc_id)
        if rec is None:
            raise HTTPException(status_code=404, detail="doc not found")
        return FetchDocResponse(doc_id=rec.doc_id, nonce_b64=rec.nonce_b64, ct_b64=rec.ct_b64, meta=rec.meta)

    @app.get("/stats", response_model=StatsResponse)
    async def stats() -> StatsResponse:
        s = storage.stats()
        return StatsResponse(**s)

    return app


app = create_app()
