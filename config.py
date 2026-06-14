from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class AppConfig:
    """Runtime configuration for the local BG Bug Scout server and scanner."""

    host: str = "127.0.0.1"
    port: int = 8765
    max_body_bytes: int = 600_000
    max_pages_limit: int = 30
    max_workers: int = 5
    request_timeout: int = 8
    log_level: str = "INFO"
    log_file: str = "bug-scout.log"


DEFAULT_CONFIG = AppConfig()
