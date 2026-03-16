"""Flask application – versioned key/value store with token auth.

Endpoints
---------
Existing:
- ``GET  /health``               – liveness check
- ``POST /token``                – obtain a Bearer token for an email
- ``POST /write``                – store a new version of a key
- ``POST /read``                 – retrieve a key (JSON envelope)
- ``POST /serve``                – retrieve a key (raw content with MIME type)

New:
- ``POST /request-token-email``  – email a one-time verification code
- ``POST /verify-email-code``    – verify emailed code and mint Bearer token
"""

import base64
import hashlib
import json
import os
import secrets
import time
from pathlib import Path

import requests
from flask import Flask, request, jsonify, Response, g
from flask_cors import CORS

from config import Config
from auth import generate_token, require_token
from storage import write_key, read_key, serve_key


EMAIL_SEND_URL = "https://16504442930.work/send_email_with_attachments"
EMAIL_CODE_TTL_SECONDS = int(os.environ.get("EMAIL_CODE_TTL_SECONDS", "600"))
EMAIL_CODE_MAX_ATTEMPTS = int(os.environ.get("EMAIL_CODE_MAX_ATTEMPTS", "5"))
EMAIL_CODE_LENGTH = int(os.environ.get("EMAIL_CODE_LENGTH", "6"))


# ---------------------------------------------------------------------------
# App factory
# ---------------------------------------------------------------------------

def create_app() -> Flask:
    """Create and configure the Flask application."""
    application = Flask(__name__)
    application.config.from_object(Config)

    # Enable CORS for all origins
    CORS(application)

    # Ensure storage directories exist
    os.makedirs(Config.STORAGE_BASE_DIR, exist_ok=True)
    os.makedirs(_email_challenge_dir(), exist_ok=True)

    _register_routes(application)
    return application


# ---------------------------------------------------------------------------
# Email challenge helpers
# ---------------------------------------------------------------------------

def _email_challenge_dir() -> str:
    return os.path.join(Config.STORAGE_BASE_DIR, "_email_challenges")


def _email_challenge_path(email: str) -> str:
    email_hash = hashlib.sha256(email.strip().lower().encode("utf-8")).hexdigest()
    return os.path.join(_email_challenge_dir(), f"{email_hash}.json")


def _code_hash(email: str, code: str) -> str:
    raw = f"{email.strip().lower()}:{code}:{Config.SECRET_KEY}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _generate_email_code() -> str:
    digits = "0123456789"
    return "".join(secrets.choice(digits) for _ in range(EMAIL_CODE_LENGTH))


def _store_email_challenge(email: str, code: str) -> dict:
    now = int(time.time())
    record = {
        "email": email.strip().lower(),
        "code_hash": _code_hash(email, code),
        "expires_at": now + EMAIL_CODE_TTL_SECONDS,
        "used": False,
        "attempts": 0,
        "created_at": now,
    }
    with open(_email_challenge_path(email), "w", encoding="utf-8") as f:
        json.dump(record, f)
    return record


def _load_email_challenge(email: str) -> dict | None:
    path = _email_challenge_path(email)
    if not os.path.exists(path):
        return None
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None


def _save_email_challenge(email: str, record: dict) -> None:
    with open(_email_challenge_path(email), "w", encoding="utf-8") as f:
        json.dump(record, f)


def _send_email_code(email: str, code: str) -> tuple[bool, str]:
    """
    Send the verification code using the external email endpoint.

    Assumed request body format:
    {
      "to": "...",
      "subject": "...",
      "body": "..."
    }

    If your send endpoint expects different field names, update only this helper.
    """
    subject = "Your verification code"
    body = (
        f"Your verification code is: {code}\n\n"
        f"This code expires in {EMAIL_CODE_TTL_SECONDS // 60} minutes."
    )

    payload = {
        "to": email,
        "subject": subject,
        "body": body,
        "attachments": [],
    }

    try:
        resp = requests.post(EMAIL_SEND_URL, json=payload, timeout=30)
        if 200 <= resp.status_code < 300:
            return True, resp.text
        return False, f"email send failed: status={resp.status_code} body={resp.text}"
    except Exception as exc:
        return False, f"email send exception: {exc}"


def _verify_email_code(email: str, code: str) -> tuple[bool, str]:
    record = _load_email_challenge(email)
    if not record:
        return False, "No verification request found for this email"

    if record.get("used"):
        return False, "Verification code already used"

    now = int(time.time())
    if now > int(record.get("expires_at", 0)):
        return False, "Verification code expired"

    attempts = int(record.get("attempts", 0))
    if attempts >= EMAIL_CODE_MAX_ATTEMPTS:
        return False, "Too many verification attempts"

    submitted_hash = _code_hash(email, code)
    expected_hash = record.get("code_hash", "")

    if not secrets.compare_digest(submitted_hash, expected_hash):
        record["attempts"] = attempts + 1
        _save_email_challenge(email, record)
        return False, "Invalid verification code"

    record["used"] = True
    _save_email_challenge(email, record)
    return True, ""


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

    @application.route("/request-token-email", methods=["POST"])
    def request_token_email():
        """Generate and email a short-lived verification code."""
        data = request.get_json(silent=True)
        if not data or "email" not in data:
            return jsonify({"error": "email is required"}), 400

        email = data["email"]
        if not isinstance(email, str) or "@" not in email:
            return jsonify({"error": "Invalid email"}), 400

        email = email.strip().lower()
        code = _generate_email_code()
        record = _store_email_challenge(email, code)
        ok, send_result = _send_email_code(email, code)

        if not ok:
            return jsonify({
                "error": "Failed to send verification email",
                "details": send_result,
            }), 502

        return jsonify({
            "message": "Verification email sent",
            "email": email,
            "expires_at": record["expires_at"],
            "send_result": send_result,
        }), 200

    @application.route("/verify-email-code", methods=["POST"])
    def verify_email_code():
        """Verify a one-time emailed code and mint a Bearer token."""
        data = request.get_json(silent=True)
        if not data or "email" not in data or "code" not in data:
            return jsonify({"error": "email and code are required"}), 400

        email = data["email"]
        code = data["code"]

        if not isinstance(email, str) or "@" not in email:
            return jsonify({"error": "Invalid email"}), 400
        if not isinstance(code, str) or not code.strip():
            return jsonify({"error": "Invalid code"}), 400

        email = email.strip().lower()
        code = code.strip()

        ok, error = _verify_email_code(email, code)
        if not ok:
            return jsonify({"error": error}), 401

        token = generate_token(email)
        return jsonify({
            "token": token,
            "email": email,
            "message": "Email verified successfully",
        }), 200

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
