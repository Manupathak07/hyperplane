#!/bin/sh
set -e

cd /code

echo "[hyperplane] Running database migrations..."
alembic upgrade head

echo "[hyperplane] Starting FastAPI on 0.0.0.0:8000..."
exec uvicorn app.main:app --host 0.0.0.0 --port 8000
