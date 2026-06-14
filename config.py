from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class AppConfig:
    """Runtime configuration for the local BG Bug Scout server and scanner."""

    host: str = "127.0.0.1"
    port: int = 8765
    max_body_bytes: int | None = None
    max_pages_limit: int | None = None
    max_workers: int | None = None
    request_timeout: int = 8
    log_level: str = "INFO"
    log_file: str = "bug-scout.log"
    response_preview_chars: int | None = None


DEFAULT_CONFIG = AppConfig()
