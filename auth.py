import json
import os
import threading
import uuid
import functools
from datetime import datetime

from flask import request, jsonify

import config

_file_lock = threading.Lock()


def _read_token_db():
    """Read the token database from the JSON file. Returns a dict."""
    with _file_lock:
        if not os.path.exists(config.TOKEN_DB_FILE):
            return {}
        try:
            with open(config.TOKEN_DB_FILE, "r") as f:
                data = json.load(f)
        except (json.JSONDecodeError, IOError):
            data = {}
    return data


def _write_token_db(data):
    """Write the token database dict to the JSON file."""
    with _file_lock:
        tmp_path = config.TOKEN_DB_FILE + ".tmp"
        with open(tmp_path, "w") as f:
            json.dump(data, f, indent=2)
        os.replace(tmp_path, config.TOKEN_DB_FILE)


def create_token(email):
    """Create a new authentication token for the given email address.

    Args:
        email: The email address to associate with the token.

    Returns:
        The generated token string (uuid4 hex).
    """
    token = str(uuid.uuid4())
    db = _read_token_db()
    db[token] = {
        "email": email,
        "created_at": datetime.utcnow().isoformat(),
        "active": True,
    }
    _write_token_db(db)
    return token


def validate_token(token):
    """Validate whether a token exists and is active.

    Args:
        token: The token string to validate.

    Returns:
        True if the token is valid and active, False otherwise.
    """
    if not token:
        return False
    db = _read_token_db()
    entry = db.get(token)
    if entry is None:
        return False
    return entry.get("active", False)


def revoke_token(token):
    """Revoke an existing token by marking it inactive.

    Args:
        token: The token string to revoke.

    Returns:
        True if the token was found and revoked, False otherwise.
    """
    db = _read_token_db()
    if token not in db:
        return False
    db[token]["active"] = False
    _write_token_db(db)
    return True


def get_token_email(token):
    """Retrieve the email address associated with a token.

    Args:
        token: The token string.

    Returns:
        The email string if the token exists, None otherwise.
    """
    db = _read_token_db()
    entry = db.get(token)
    if entry is None:
        return None
    return entry.get("email")


def _extract_bearer_token():
    """Extract the bearer token from the Authorization header.

    Returns:
        The token string or None if not present / malformed.
    """
    auth_header = request.headers.get("Authorization", "")
    if not auth_header:
        return None
    parts = auth_header.split()
    if len(parts) != 2 or parts[0].lower() != "bearer":
        return None
    return parts[1]


def require_token(f):
    """Flask route decorator that enforces Bearer token authentication.

    Usage:
        @app.route("/protected")
        @require_token
        def protected_view():
            ...

    The decorator checks for an ``Authorization: Bearer <token>`` header.
    If the token is missing, malformed, or invalid the request is rejected
    with an appropriate HTTP error response.  On success the wrapped view
    function is called normally.
    """

    @functools.wraps(f)
    def decorated(*args, **kwargs):
        token = _extract_bearer_token()
        if token is None:
            return jsonify({"error": "Missing or malformed Authorization header. Expected 'Bearer <token>'."}), 401
        if not validate_token(token):
            return jsonify({"error": "Invalid or revoked token."}), 403
        return f(*args, **kwargs)

    return decorated