from __future__ import annotations

import json
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional


@dataclass
class StoredDoc:
    doc_id: str
    nonce_b64: str
    ct_b64: str
    meta: Dict[str, Any]


class JsonStorage:
    """
    Persistent JSON storage for:
      - docs: doc_id -> {nonce_b64, ct_b64, meta}
      - index: token_b64url -> [doc_id, ...]
    Saved at data/state.json
    """

    def __init__(self, state_path: Path):
        self._lock = threading.Lock()
        self.state_path = state_path
        self.state_path.parent.mkdir(parents=True, exist_ok=True)

        self._docs: Dict[str, Dict[str, Any]] = {}
        self._index: Dict[str, List[str]] = {}
        self.load()

    def load(self) -> None:
        with self._lock:
            if not self.state_path.exists():
                self._docs = {}
                self._index = {}
                self._save_locked()
                return
            data = json.loads(self.state_path.read_text(encoding="utf-8"))
            self._docs = data.get("docs", {})
            self._index = data.get("index", {})

            if not isinstance(self._docs, dict):
                self._docs = {}
            if not isinstance(self._index, dict):
                self._index = {}

    def _save_locked(self) -> None:
        tmp_path = self.state_path.with_suffix(".json.tmp")
        data = {"docs": self._docs, "index": self._index}
        tmp_path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
        tmp_path.replace(self.state_path)

    def save(self) -> None:
        with self._lock:
            self._save_locked()

    def doc_exists(self, doc_id: str) -> bool:
        with self._lock:
            return doc_id in self._docs

    def add_doc(self, doc: StoredDoc, tokens: List[str]) -> None:
        tokens_dedup = list(dict.fromkeys(tokens))  # stable dedup
        with self._lock:
            if doc.doc_id in self._docs:
                raise ValueError(f"doc_id already exists: {doc.doc_id}")

            self._docs[doc.doc_id] = {
                "nonce_b64": doc.nonce_b64,
                "ct_b64": doc.ct_b64,
                "meta": doc.meta,
            }

            for tok in tokens_dedup:
                posting = self._index.get(tok)
                if posting is None:
                    self._index[tok] = [doc.doc_id]
                else:
                    if doc.doc_id not in posting:
                        posting.append(doc.doc_id)

            self._save_locked()

    def get_doc(self, doc_id: str) -> Optional[StoredDoc]:
        with self._lock:
            rec = self._docs.get(doc_id)
            if rec is None:
                return None
            return StoredDoc(
                doc_id=doc_id,
                nonce_b64=rec["nonce_b64"],
                ct_b64=rec["ct_b64"],
                meta=rec.get("meta", {}) or {},
            )

    def search(self, token_b64url: str) -> List[str]:
        with self._lock:
            return list(self._index.get(token_b64url, []))

    def stats(self) -> Dict[str, int]:
        with self._lock:
            doc_count = len(self._docs)
            token_count = len(self._index)
            total_postings = sum(len(v) for v in self._index.values())
            return {
                "doc_count": doc_count,
                "token_count": token_count,
                "total_index_postings": total_postings,
            }
