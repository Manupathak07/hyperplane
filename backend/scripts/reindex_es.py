"""Reindex all Postgres incidents into Elasticsearch.

Run after first deploying the search index, or whenever ES has been wiped /
drifted from Postgres. Idempotent — uses the Incident UUID as the ES `_id`.

Usage (from host):
    docker exec hyperplane-backend python -m scripts.reindex_es

Or with explicit env:
    HYPERPLANE_DB_URL=... python -m scripts.reindex_es
"""
from __future__ import annotations

import asyncio

from sqlalchemy.ext.asyncio import AsyncSession

from app.db import AsyncSessionLocal
from app.search import close_es, ensure_index
from app.search.indexer import reindex_all


async def main() -> None:
    await ensure_index()
    async with AsyncSessionLocal() as session:  # type: AsyncSession
        n = await reindex_all(session)
    await close_es()
    print(f"reindexed {n} incidents into Elasticsearch")


if __name__ == "__main__":
    asyncio.run(main())