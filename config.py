"""Application configuration."""

import os


class Config:
    """Configuration loaded from environment variables with sensible defaults."""

    STORAGE_BASE_DIR = os.environ.get("STORAGE_BASE_DIR", "/data/store")
    PORT = int(os.environ.get("PORT", 8080))
    FLASK_ENV = os.environ.get("FLASK_ENV", "production")
    SECRET_KEY = os.environ.get("SECRET_KEY", "default-secret-key-change-me")
    HOST = "0.0.0.0"
