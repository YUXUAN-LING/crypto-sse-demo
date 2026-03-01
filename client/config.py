from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Literal, Optional, Tuple

from common.crypto import (
    DerivedKeys,
    derive_master_key_scrypt,
    derive_subkeys_hkdf,
    hmac_verify_sha256,
    make_config_check,
)
from common.utils import b64_decode, b64_encode


ConfigMode = Literal["passphrase", "keyfile"]


@dataclass
class ClientConfig:
    version: int
    server_url: str
    mode: ConfigMode

    # passphrase mode
    scrypt_salt_b64: Optional[str] = None
    scrypt_n: Optional[int] = None
    scrypt_r: Optional[int] = None
    scrypt_p: Optional[int] = None
    scrypt_len: Optional[int] = None
    config_check_b64: Optional[str] = None

    # keyfile mode
    keyfile_path: Optional[str] = None

    @staticmethod
    def default_path() -> Path:
        # Per requirements, store config in client/config.json
        return Path(__file__).resolve().parent / "config.json"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "version": self.version,
            "server_url": self.server_url,
            "mode": self.mode,
            "scrypt": {
                "salt_b64": self.scrypt_salt_b64,
                "n": self.scrypt_n,
                "r": self.scrypt_r,
                "p": self.scrypt_p,
                "length": self.scrypt_len,
                "check_b64": self.config_check_b64,
            },
            "keyfile": {
                "path": self.keyfile_path,
            },
        }

    @staticmethod
    def from_dict(d: Dict[str, Any]) -> "ClientConfig":
        scrypt = d.get("scrypt", {}) or {}
        keyfile = d.get("keyfile", {}) or {}
        return ClientConfig(
            version=int(d.get("version", 1)),
            server_url=str(d.get("server_url", "http://127.0.0.1:8000")),
            mode=str(d.get("mode", "passphrase")),  # type: ignore
            scrypt_salt_b64=scrypt.get("salt_b64"),
            scrypt_n=scrypt.get("n"),
            scrypt_r=scrypt.get("r"),
            scrypt_p=scrypt.get("p"),
            scrypt_len=scrypt.get("length"),
            config_check_b64=scrypt.get("check_b64"),
            keyfile_path=keyfile.get("path"),
        )

    def save(self, path: Optional[Path] = None) -> None:
        path = path or self.default_path()
        path.write_text(json.dumps(self.to_dict(), ensure_ascii=False, indent=2), encoding="utf-8")

    @staticmethod
    def load(path: Optional[Path] = None) -> "ClientConfig":
        path = path or ClientConfig.default_path()
        if not path.exists():
            raise FileNotFoundError(f"Config file not found: {path}")
        d = json.loads(path.read_text(encoding="utf-8"))
        return ClientConfig.from_dict(d)


def init_passphrase_config(
    server_url: str,
    passphrase: str,
    salt: bytes,
    n: int = 2**14,
    r: int = 8,
    p: int = 1,
    length: int = 32,
) -> ClientConfig:
    k_master = derive_master_key_scrypt(passphrase.encode("utf-8"), salt=salt, n=n, r=r, p=p, length=length)
    check = make_config_check(k_master)
    return ClientConfig(
        version=1,
        server_url=server_url,
        mode="passphrase",
        scrypt_salt_b64=b64_encode(salt),
        scrypt_n=n,
        scrypt_r=r,
        scrypt_p=p,
        scrypt_len=length,
        config_check_b64=b64_encode(check),
    )


def init_keyfile_config(server_url: str, keyfile_path: Path, k_master: bytes) -> ClientConfig:
    keyfile_path.write_bytes(k_master)
    return ClientConfig(version=1, server_url=server_url, mode="keyfile", keyfile_path=str(keyfile_path))


def load_keys_from_config(cfg: ClientConfig, passphrase: Optional[str] = None) -> Tuple[bytes, DerivedKeys]:
    """
    Returns (K_master, DerivedKeys).
    In passphrase mode, require passphrase and validate via stored config_check.
    """
    if cfg.mode == "keyfile":
        if not cfg.keyfile_path:
            raise ValueError("keyfile mode requires keyfile_path in config")
        k_master = Path(cfg.keyfile_path).read_bytes()
        return k_master, derive_subkeys_hkdf(k_master)

    # passphrase mode:
    if passphrase is None:
        raise ValueError("passphrase is required for passphrase mode")

    if not (cfg.scrypt_salt_b64 and cfg.scrypt_n and cfg.scrypt_r and cfg.scrypt_p and cfg.scrypt_len):
        raise ValueError("invalid scrypt config fields")

    salt = b64_decode(cfg.scrypt_salt_b64)
    k_master = derive_master_key_scrypt(
        passphrase.encode("utf-8"),
        salt=salt,
        n=int(cfg.scrypt_n),
        r=int(cfg.scrypt_r),
        p=int(cfg.scrypt_p),
        length=int(cfg.scrypt_len),
    )

    if not cfg.config_check_b64:
        raise ValueError("missing config_check_b64")
    expected = b64_decode(cfg.config_check_b64)
    if not hmac_verify_sha256(k_master, b"SSE_CONFIG_CHECK_V1", expected):
        raise ValueError("passphrase verification failed (wrong passphrase?)")

    return k_master, derive_subkeys_hkdf(k_master)
