"""Application settings loaded from environment / .env file."""
from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    # --- Core ---
    environment: str = "dev"
    log_level: str = "INFO"

    # --- Postgres ---
    database_url: str = (
        "postgresql+asyncpg://hyperplane:hyperplane_dev@postgres:5432/hyperplane"
    )

    # --- Elasticsearch ---
    elasticsearch_url: str = "http://elasticsearch:9200"

    # --- LLM (pluggable) ---
    llm_provider: str = "ollama"
    llm_model: str = "llama3.1:8b"
    ollama_host: str = "http://host.docker.internal:11434"

    # --- Ingestion auth (Week 4) ---
    # If empty/unset, POST /events is open. If set, X-API-Key header must match.
    events_api_key: str = ""

    # --- Threat Intel (Week 6) ---
    # Leave empty to use the deterministic IP-heuristic fallback (RFC5737 +
    # private). Set both to enable live OTX + AbuseIPDB lookups.
    # Free tier limits are fine for demo traffic.
    otx_api_key: str = ""
    abuseipdb_api_key: str = ""
    # In-process TTL for the lookup cache, in seconds.
    threatintel_cache_ttl_s: int = 3600

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
