#!/bin/bash
set -e

export FLASK_ENV=${FLASK_ENV:-development}
export PORT=${PORT:-8080}
export STORAGE_BASE_DIR=${STORAGE_BASE_DIR:-/data/store}
mkdir -p "$STORAGE_BASE_DIR"

if [ "$FLASK_ENV" = "production" ]; then
  exec gunicorn --bind "0.0.0.0:$PORT" --workers 2 app:app
else
  exec python app.py
fi
