import os
import secrets


class Config:
    """Configuration class for the Flask versioned key-value store application."""

    # Secret key for session management and CSRF protection
    SECRET_KEY = os.environ.get('SECRET_KEY', secrets.token_hex(32))

    # Base directory for storing key-value data
    STORAGE_DIR = os.environ.get('STORAGE_DIR', 'data')

    # Depth of nested directory structure for organizing stored files
    # e.g., depth=3 with key "abcdef" -> a/b/c/abcdef
    DIRECTORY_DEPTH = int(os.environ.get('DIRECTORY_DEPTH', 3))

    # Self-signed HTTPS certificate and key file paths
    CERT_FILE = os.environ.get('CERT_FILE', os.path.join('certs', 'cert.pem'))
    KEY_FILE = os.environ.get('KEY_FILE', os.path.join('certs', 'key.pem'))

    # Token database file for authentication token storage
    TOKEN_DB_FILE = os.environ.get('TOKEN_DB_FILE', os.path.join('data', 'tokens.db'))