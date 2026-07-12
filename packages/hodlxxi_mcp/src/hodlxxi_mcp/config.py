from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlsplit


@dataclass(frozen=True, slots=True)
class ClientConfig:
    """Immutable outbound HTTP policy for the read-only wrapper."""

    base_url: str = "https://hodlxxi.com"
    timeout_seconds: float = 10.0
    max_response_bytes: int = 2 * 1024 * 1024
    user_agent: str = "hodlxxi-mcp/0.1.0"

    def __post_init__(self) -> None:
        parsed = urlsplit(self.base_url)
        if (
            parsed.scheme != "https"
            or parsed.hostname != "hodlxxi.com"
            or parsed.port not in (None, 443)
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
            or parsed.path not in ("", "/")
        ):
            raise ValueError("base_url must be exactly https://hodlxxi.com")
        if self.timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        if self.max_response_bytes < 1024:
            raise ValueError("max_response_bytes must be at least 1024")
        object.__setattr__(self, "base_url", "https://hodlxxi.com")
