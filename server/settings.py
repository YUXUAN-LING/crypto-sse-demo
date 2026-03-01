from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Settings:
    repo_root: Path
    data_dir: Path
    state_path: Path


def get_settings() -> Settings:
    """
    Resolve repo root and data directory.
    - Default data dir: <repo_root>/data
    - Override: env SSE_DATA_DIR
    """
    repo_root = Path(__file__).resolve().parents[1]
    data_dir_env = os.getenv("SSE_DATA_DIR", "").strip()
    data_dir = Path(data_dir_env) if data_dir_env else (repo_root / "data")
    state_path = data_dir / "state.json"
    return Settings(repo_root=repo_root, data_dir=data_dir, state_path=state_path)
