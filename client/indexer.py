from __future__ import annotations

import re
from pathlib import Path
from typing import Iterable, Set


# A simple tokenization pattern:
# - English letters/numbers
# - Common CJK block (basic demo; real Chinese segmentation is more complex)
TOKEN_RE = re.compile(r"[A-Za-z0-9\u4e00-\u9fff]+")


def normalize_keyword(s: str) -> str:
    """
    Normalize a keyword for token generation:
    - lowercase
    - strip spaces
    - remove punctuation by re-tokenizing and joining with single space
    """
    s = (s or "").strip().lower()
    parts = TOKEN_RE.findall(s)
    return " ".join(parts)


def extract_keywords(text: str) -> Set[str]:
    """
    Extract normalized keywords from document text.
    Keep it simple and replaceable for future improvements.
    """
    parts = TOKEN_RE.findall((text or "").lower())
    kw = {p.strip() for p in parts if p.strip()}
    return kw


def extract_keywords_from_file(path: Path) -> Set[str]:
    """
    Read a text file (utf-8 best effort) and extract keywords.
    """
    raw = path.read_text(encoding="utf-8", errors="ignore")
    return extract_keywords(raw)


def iter_txt_files(folder: Path) -> Iterable[Path]:
    for p in folder.rglob("*.txt"):
        if p.is_file():
            yield p
