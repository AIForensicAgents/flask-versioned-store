import os


class Config:
    STORAGE_BASE_DIR = os.environ.get("STORAGE_BASE_DIR", "/data/store")
    PORT = int(os.environ.get("PORT", 8080))
    FLASK_ENV = os.environ.get("FLASK_ENV", "production")
    SECRET_KEY = os.urandom(32)
    HOST = "0.0.0.0"