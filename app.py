"""Flask application – versioned key/value store with token auth.

Endpoints
---------
- ``GET  /health`` – liveness check
- ``POST /token``  – obtain a Bearer token for an email
- ``POST /write``  – store a new version of a key
- ``POST /read``   – retrieve a key (JSON envelope)
- ``POST /serve``  – retrieve a key (raw content with MIME type)
"""

import base64
import json
import os

from flask import Flask, request, jsonify, Response, g
from flask_cors import CORS

from config import Config
from auth import generate_token, require_token
from storage import write_key, read_key, serve_key

# ---------------------------------------------------------------------------
# App factory
# ---------------------------------------------------------------------------

def create_app() -> Flask:
    """Create and configure the Flask application."""
    application = Flask(__name__)
    application.config.from_object(Config)

    # Enable CORS for all origins
    CORS(application)

    # Ensure the storage directory exists
    os.makedirs(Config.STORAGE_BASE_DIR, exist_ok=True)

    _register_routes(application)
    return application


# ---------------------------------------------------------------------------
# Route registration
# ---------------------------------------------------------------------------

def _register_routes(application: Flask) -> None:
    """Register all route handlers on *application*."""

    @application.route("/health", methods=["GET"])
    def health():
        """Simple liveness probe."""
        return jsonify({"status": "healthy"}), 200

    @application.route("/token", methods=["POST"])
    def create_token():
        """Generate a Bearer token for the provided email address."""
        data = request.get_json(silent=True)
        if not data or "email" not in data:
            return jsonify({"error": "email is required"}), 400

        email = data["email"]
        if not isinstance(email, str) or "@" not in email:
            return jsonify({"error": "Invalid email"}), 400

        token = generate_token(email)
        return jsonify({"token": token, "email": email}), 200

    @application.route("/write", methods=["POST"])
    @require_token
    def write():
        """Store a new version of a key.

        Accepts either JSON (``application/json``) or multipart form data
        with an optional ``file`` upload.
        """
        content_type_header = request.content_type or ""
        email = g.email

        if "application/json" in content_type_header:
            data = request.get_json(silent=True)
            if not data or "key" not in data:
                return jsonify({"error": "key is required"}), 400

            key = data["key"]
            value = data.get("value", "")
            ct = data.get("content_type", "application/octet-stream")

            # Serialise complex values to JSON
            if isinstance(value, (dict, list)):
                value = json.dumps(value)
                if ct == "application/octet-stream":
                    ct = "application/json"
        else:
            key = request.form.get("key")
            if not key:
                return jsonify({"error": "key is required"}), 400

            if "file" in request.files:
                file = request.files["file"]
                value = file.read()
                ct = file.content_type or "application/octet-stream"
            else:
                value = request.form.get("value", "")
                ct = request.form.get("content_type", "application/octet-stream")

        version, error = write_key(
            Config.STORAGE_BASE_DIR, key, value, email, content_type=ct
        )

        if error:
            return jsonify({"error": error}), 403

        return jsonify({"key": key, "version": version, "message": "Written successfully"}), 200

    @application.route("/read", methods=["POST"])
    @require_token
    def read():
        """Read the latest (or a specific) version of a key."""
        data = request.get_json(silent=True)
        if not data or "key" not in data:
            return jsonify({"error": "key is required"}), 400

        key = data["key"]
        version = data.get("version")
        email = g.email

        content, meta, error = read_key(
            Config.STORAGE_BASE_DIR, key, email, version
        )

        if error:
            status = 403 if "Forbidden" in error else 404
            return jsonify({"error": error}), status

        # Attempt to present the value in a friendly way
        try:
            value = content.decode("utf-8")
            try:
                value = json.loads(value)
            except (json.JSONDecodeError, ValueError):
                pass
        except (UnicodeDecodeError, AttributeError):
            value = base64.b64encode(content).decode("utf-8")

        return jsonify({
            "key": key,
            "value": value,
            "version": meta.get("version"),
            "content_type": meta.get("content_type", "application/octet-stream"),
        }), 200

    @application.route("/serve", methods=["POST"])
    @require_token
    def serve():
        """Serve the raw content of a key with its original MIME type."""
        data = request.get_json(silent=True)
        if not data or "key" not in data:
            return jsonify({"error": "key is required"}), 400

        key = data["key"]
        version = data.get("version")
        email = g.email

        content, content_type, error = serve_key(
            Config.STORAGE_BASE_DIR, key, email, version
        )

        if error:
            status = 403 if "Forbidden" in error else 404
            return jsonify({"error": error}), status

        return Response(content, mimetype=content_type)


# ---------------------------------------------------------------------------
# Module-level app instance (used by gunicorn: ``app:app``)
# ---------------------------------------------------------------------------

app = create_app()

if __name__ == "__main__":
    app.run(host=Config.HOST, port=Config.PORT)
