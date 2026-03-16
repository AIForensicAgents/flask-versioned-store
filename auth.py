"""Authentication module.

Provides HMAC-based token generation and validation, plus a Flask
decorator that enforces Bearer-token authentication on routes.
"""

import base64
import hashlib
import hmac
import time
from functools import wraps

from flask import request, jsonify, g

from config import Config


def generate_token(email: str) -> str:
    """Generate an HMAC-signed Bearer token for the given email.

    The token encodes ``email:timestamp:signature`` in URL-safe base-64.
    """
    timestamp = str(int(time.time()))
    payload = f"{email}:{timestamp}"
    signature = hmac.new(
        Config.SECRET_KEY.encode("utf-8"),
        payload.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    token_data = f"{payload}:{signature}"
    return base64.urlsafe_b64encode(token_data.encode("utf-8")).decode("utf-8")


def validate_token(token: str) -> bool:
    """Return True if *token* carries a valid HMAC signature."""
    try:
        token_data = base64.urlsafe_b64decode(token.encode("utf-8")).decode("utf-8")
        parts = token_data.rsplit(":", 2)
        if len(parts) != 3:
            return False
        email, timestamp, signature = parts
        payload = f"{email}:{timestamp}"
        expected = hmac.new(
            Config.SECRET_KEY.encode("utf-8"),
            payload.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        return hmac.compare_digest(signature, expected)
    except Exception:
        return False


def get_email_from_token(token: str) -> str | None:
    """Extract the email address embedded in *token*, or None on failure."""
    try:
        token_data = base64.urlsafe_b64decode(token.encode("utf-8")).decode("utf-8")
        parts = token_data.rsplit(":", 2)
        if len(parts) != 3:
            return None
        return parts[0]
    except Exception:
        return None


def require_token(f):
    """Decorator that enforces a valid Bearer token.

    On success the authenticated email is available as ``g.email``
    and the raw token as ``g.token``.
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return jsonify({"error": "Missing or invalid Authorization header"}), 401

        token = auth_header[7:]

        if not validate_token(token):
            return jsonify({"error": "Invalid or expired token"}), 401

        email = get_email_from_token(token)
        if not email:
            return jsonify({"error": "Could not extract email from token"}), 401

        g.email = email
        g.token = token
        return f(*args, **kwargs)

    return decorated
