from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional

import requests


@dataclass
class SSEServerClient:
    base_url: str
    timeout_s: float = 10.0

    def _url(self, path: str) -> str:
        return self.base_url.rstrip("/") + path

    def health(self) -> Dict[str, Any]:
        r = requests.post(self._url("/health"), timeout=self.timeout_s)
        r.raise_for_status()
        return r.json()

    def upload_doc(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        r = requests.post(self._url("/upload_doc"), json=payload, timeout=self.timeout_s)
        r.raise_for_status()
        return r.json()

    def search(self, token_b64url: str) -> Dict[str, Any]:
        r = requests.post(self._url("/search"), json={"token_b64url": token_b64url}, timeout=self.timeout_s)
        r.raise_for_status()
        return r.json()

    def fetch(self, doc_id: str) -> Dict[str, Any]:
        r = requests.get(self._url(f"/fetch/{doc_id}"), timeout=self.timeout_s)
        r.raise_for_status()
        return r.json()

    def stats(self) -> Dict[str, Any]:
        r = requests.get(self._url("/stats"), timeout=self.timeout_s)
        r.raise_for_status()
        return r.json()
