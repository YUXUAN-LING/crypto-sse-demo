from __future__ import annotations

from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class HealthResponse(BaseModel):
    status: str = "ok"


class UploadDocRequest(BaseModel):
    doc_id: str = Field(..., min_length=1)
    nonce_b64: str = Field(..., min_length=1)
    ct_b64: str = Field(..., min_length=1)
    meta: Dict[str, Any] = Field(default_factory=dict)
    tokens: List[str] = Field(..., min_length=1)


class UploadDocResponse(BaseModel):
    status: str
    doc_id: str


class SearchRequest(BaseModel):
    token_b64url: str = Field(..., min_length=1)


class EncryptedDocBundle(BaseModel):
    doc_id: str
    nonce_b64: str
    ct_b64: str
    meta: Dict[str, Any] = Field(default_factory=dict)


class SearchResponse(BaseModel):
    doc_ids: List[str] = Field(default_factory=list)
    docs: List[EncryptedDocBundle] = Field(default_factory=list)


class FetchDocResponse(EncryptedDocBundle):
    pass


class StatsResponse(BaseModel):
    doc_count: int
    token_count: int
    total_index_postings: int
