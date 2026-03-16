import uuid
from functools import wraps

from flask import request, g, jsonify

_token_store: dict[str, str] = {}


def generate_token(email: str) -> str:
    token = str(uuid.uuid4())
    _token_store[token] = email
    return token


def validate_token(token: str) -> bool:
    return token in _token_store


def get_email_from_token(token: str) -> str | None:
    return _token_store.get(token)


def require_token():
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            auth_header = request.headers.get("Authorization")

            if not auth_header:
                return jsonify({"error": "Missing Authorization header"}), 401

            parts = auth_header.split()

            if len(parts) != 2 or parts[0] != "Bearer":
                return jsonify({"error": "Invalid Authorization header format. Expected 'Bearer <token>'"}), 401

            token = parts[1]

            if not validate_token(token):
                return jsonify({"error": "Invalid or expired token"}), 401

            g.email = get_email_from_token(token)

            return f(*args, **kwargs)

        return decorated_function

    return decorator