"""Central configuration. Secrets come from the environment only, never from code."""
import os
from dataclasses import dataclass

from dotenv import load_dotenv

load_dotenv()


class ConfigError(RuntimeError):
    pass


class Secret:
    """Wrapper that refuses to reveal its value in repr/str/logs/tracebacks."""

    __slots__ = ("_value",)

    def __init__(self, value: str):
        self._value = value

    def reveal(self) -> str:
        return self._value

    def __repr__(self) -> str:
        return "Secret(***)"

    __str__ = __repr__


@dataclass(frozen=True)
class Settings:
    api_key: Secret
    api_url: str = "https://api.anthropic.com/v1/messages"
    api_version: str = "2023-06-01"
    model: str = "claude-sonnet-5-5"
    max_output_tokens: int = 1024

    # Time limits (seconds). Every request has hard bounds at every layer.
    connect_timeout_s: float = 5.0
    read_timeout_s: float = 30.0      # per attempt
    write_timeout_s: float = 10.0
    pool_timeout_s: float = 5.0
    total_timeout_s: float = 45.0     # across ALL attempts + backoff sleeps

    # Retry policy (bounded)
    max_attempts: int = 4             # 1 initial try + 3 retries
    backoff_base_s: float = 0.5
    backoff_max_s: float = 8.0

    # Input / load limits
    max_log_chars: int = 100_000
    max_concurrency: int = 8

    log_level: str = "INFO"


def _env_num(name: str, default, cast):
    raw = os.getenv(name)
    if raw is None or raw == "":
        return default
    try:
        value = cast(raw)
    except ValueError as exc:
        raise ConfigError(f"{name} must be a valid {cast.__name__}") from exc
    if value <= 0:
        raise ConfigError(f"{name} must be > 0")
    return value


def load_settings() -> Settings:
    key = os.getenv("ANTHROPIC_API_KEY", "").strip()
    if not key or key == "replace-me":
        # Message deliberately never includes any key material.
        raise ConfigError("ANTHROPIC_API_KEY is not set. Add it to .env or your secret manager.")

    d = Settings(api_key=Secret(key))
    return Settings(
        api_key=Secret(key),
        model=os.getenv("LLM_MODEL", d.model),
        max_attempts=_env_num("LLM_MAX_ATTEMPTS", d.max_attempts, int),
        total_timeout_s=_env_num("LLM_TOTAL_TIMEOUT_S", d.total_timeout_s, float),
        read_timeout_s=_env_num("LLM_READ_TIMEOUT_S", d.read_timeout_s, float),
        max_log_chars=_env_num("MAX_LOG_CHARS", d.max_log_chars, int),
        max_concurrency=_env_num("MAX_CONCURRENCY", d.max_concurrency, int),
        log_level=os.getenv("LOG_LEVEL", d.log_level).upper(),
    )
