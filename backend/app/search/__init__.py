"""Elasticsearch client + index lifecycle.

Single AsyncElasticsearch client reused across requests. The client is created
lazily on first use (so the backend can boot even if ES is briefly down) and
closed cleanly on shutdown.

Index: `hp-incidents` — one document per Incident row, written by
`app.search.indexer.index_incident()` after each successful Postgres insert.
"""
from __future__ import annotations

import logging
from typing import Optional

from elasticsearch import AsyncElasticsearch

from app.config import settings

log = logging.getLogger(__name__)

INDEX_NAME = "hp-incidents"

# Document mapping. Tuned for the dashboard's filtering + free-text search:
#   - `keyword` fields are exact-match (filtering, aggregations, sort)
#   - `text` fields are analysed (full-text search, scored relevance)
#   - `date` fields are range-queryable
INCIDENT_MAPPING: dict = {
    "mappings": {
        "properties": {
            "id": {"type": "keyword"},
            "event_id": {"type": "keyword"},
            "correlation_id": {"type": "keyword"},
            "title": {"type": "text", "fields": {"raw": {"type": "keyword"}}},
            "description": {"type": "text"},
            "event_type": {"type": "keyword"},
            "domain": {"type": "keyword"},
            "severity": {"type": "keyword"},        # enum: low|medium|high|critical
            "severity_numeric": {"type": "integer"},
            "status": {"type": "keyword"},          # enum: new|triaging|...
            "source": {"type": "keyword"},
            "src": {"type": "ip", "null_value": None},
            "user": {"type": "keyword"},
            "host": {"type": "keyword"},
            "asset_id": {"type": "keyword"},
            "tags": {"type": "keyword"},
            "labels": {"type": "object", "enabled": True},
            "raw": {"type": "text"},
            "created_at": {"type": "date"},
            "updated_at": {"type": "date"},
        }
    },
    "settings": {
        "number_of_shards": 1,
        "number_of_replicas": 0,  # single-node ES in dev; bump for prod
    },
}


_client: Optional[AsyncElasticsearch] = None


def get_es() -> AsyncElasticsearch:
    """Return the shared AsyncElasticsearch client. Created lazily so the
    backend can boot before ES is ready (the docker-compose healthcheck will
    block start until ES is up, but a transient blip shouldn't 500 every
    request).
    """
    global _client
    if _client is None:
        _client = AsyncElasticsearch(hosts=[settings.elasticsearch_url])
    return _client


async def close_es() -> None:
    """Close the client on shutdown so connections don't leak."""
    global _client
    if _client is not None:
        await _client.close()
        _client = None


async def ensure_index() -> None:
    """Create the incidents index if it doesn't exist. Idempotent.

    Called once at app startup (in the lifespan). If ES is unreachable we log
    and move on — the rest of the app still works, we just lose search.
    """
    es = get_es()
    try:
        exists = await es.indices.exists(index=INDEX_NAME)
        if not exists:
            await es.indices.create(index=INDEX_NAME, body=INCIDENT_MAPPING)
            log.info("created ES index %s", INDEX_NAME)
        else:
            log.info("ES index %s already exists", INDEX_NAME)
    except Exception as e:
        log.warning("could not ensure ES index %s: %s", INDEX_NAME, e)