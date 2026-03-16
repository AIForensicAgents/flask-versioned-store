import os
import json
import time
import hmac
import base64
import hashlib
import mimetypes
from functools import wraps
from typing import Optional, Tuple, Any

from flask import Flask, request, jsonify, Response, g
from flask_cors import CORS


class Config:
    STORAGE_BASE_DIR = os.environ.get("STORAGE_BASE_DIR", "/data/store")
    PORT = int(os.environ.get("PORT", 8080))
    SECRET_KEY = os.environ.get("SECRET_KEY", "default-secret-key-change-me")


app = Flask(__name__)
app.config.from_object(Config)

# Public browser access
CORS(
    app,
    resources={r"/*": {"origins": "*"}},
    allow_headers=["Content-Type", "Authorization"],
    methods=["GET", "POST", "OPTIONS"],
    supports_credentials=False,
)


def json_error(message: str, status: int):
    return jsonify({"error": message}), status


def ensure_storage_base():
    os.makedirs(Config.STORAGE_BASE_DIR, exist_ok=True)


def safe_json_body() -> Optional[dict]:
    return request.get_json(silent=True)


# =========================
# Auth
# =========================

def generate_token(email: str) -> str:
    timestamp = str(int(time.time()))
    payload = f"{email}:{timestamp}"
    signature = hmac.new(
        Config.SECRET_KEY.encode("utf-8"),
        payload.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    token_data = f"{payload}:{signature}"
    return base64.urlsafe_b64encode(token_data.encode("utf-8")).decode("utf-8")


def decode_token(token: str) -> Optional[Tuple[str, str, str]]:
    try:
        token_data = base64.urlsafe_b64decode(token.encode("utf-8")).decode("utf-8")
        parts = token_data.rsplit(":", 2)
        if len(parts) != 3:
            return None
        email, timestamp, signature = parts
        return email, timestamp, signature
    except Exception:
        return None


def validate_token(token: str) -> bool:
    decoded = decode_token(token)
    if not decoded:
        return False

    email, timestamp, signature = decoded
    payload = f"{email}:{timestamp}"
    expected_signature = hmac.new(
        Config.SECRET_KEY.encode("utf-8"),
        payload.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()

    return hmac.compare_digest(signature, expected_signature)


def get_email_from_token(token: str) -> Optional[str]:
    decoded = decode_token(token)
    if not decoded:
        return None
    email, _, _ = decoded
    return email


def require_token(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return json_error("Missing or invalid Authorization header", 401)

        token = auth_header[len("Bearer "):].strip()
        if not token:
            return json_error("Missing or invalid Authorization header", 401)

        if not validate_token(token):
            return json_error("Invalid token", 401)

        email = get_email_from_token(token)
        if not email:
            return json_error("Could not extract email from token", 401)

        g.auth_email = email
        g.auth_token = token
        return fn(*args, **kwargs)

    return wrapper


# =========================
# Storage paths + metadata
# =========================

def get_key_hash(key: str) -> str:
    return hashlib.sha256(key.encode("utf-8")).hexdigest()


def get_key_dir(key: str) -> str:
    h = get_key_hash(key)
    return os.path.join(
        Config.STORAGE_BASE_DIR,
        h[:2],
        h[2:4],
        h[4:6],
        h,
    )


def get_owner_path(key_dir: str) -> str:
    return os.path.join(key_dir, "owner.json")


def get_versions_dir(key_dir: str) -> str:
    return os.path.join(key_dir, "versions")


def get_meta_path(versions_dir: str, version: int) -> str:
    return os.path.join(versions_dir, f"v{version}.meta.json")


def get_owner(key_dir: str) -> Optional[str]:
    owner_path = get_owner_path(key_dir)
    if not os.path.exists(owner_path):
        return None

    try:
        with open(owner_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data.get("email")
    except Exception:
        return None


def set_owner(key_dir: str, email: str) -> None:
    os.makedirs(key_dir, exist_ok=True)
    owner_path = get_owner_path(key_dir)
    with open(owner_path, "w", encoding="utf-8") as f:
        json.dump({"email": email}, f)


def get_next_version(key_dir: str) -> int:
    versions_dir = get_versions_dir(key_dir)
    if not os.path.exists(versions_dir):
        return 1

    versions = []
    for fname in os.listdir(versions_dir):
        if fname.endswith(".meta.json"):
            continue
        if not fname.startswith("v"):
            continue
        try:
            version_str = fname[1:].split(".", 1)[0]
            versions.append(int(version_str))
        except Exception:
            continue

    return (max(versions) + 1) if versions else 1


def get_latest_version_file(key_dir: str) -> Optional[Tuple[int, str]]:
    versions_dir = get_versions_dir(key_dir)
    if not os.path.exists(versions_dir):
        return None

    found = []
    for fname in os.listdir(versions_dir):
        if fname.endswith(".meta.json"):
            continue
        if not fname.startswith("v"):
            continue
        try:
            version_str = fname[1:].split(".", 1)[0]
            found.append((int(version_str), fname))
        except Exception:
            continue

    if not found:
        return None

    found.sort(key=lambda x: x[0], reverse=True)
    return found[0]


def load_meta(versions_dir: str, version: int, fallback_filename: Optional[str] = None) -> dict:
    meta_path = get_meta_path(versions_dir, version)
    if os.path.exists(meta_path):
        try:
            with open(meta_path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass

    return {
        "version": version,
        "content_type": "application/octet-stream",
        "filename": fallback_filename or f"v{version}",
    }


def find_version_filename(versions_dir: str, version: int) -> Optional[str]:
    prefix = f"v{version}"
    for fname in os.listdir(versions_dir):
        if fname.endswith(".meta.json"):
            continue
        if fname.startswith(prefix):
            return fname
    return None


def guess_extension_from_content_type(content_type: Optional[str]) -> str:
    if not content_type:
        return ""
    guessed = mimetypes.guess_extension(content_type)
    return guessed or ""


# =========================
# Storage operations
# =========================

def write_key(key: str, value: Any, email: str, content_type: Optional[str] = None) -> Tuple[Optional[int], Optional[str]]:
    key_dir = get_key_dir(key)
    versions_dir = get_versions_dir(key_dir)
    os.makedirs(versions_dir, exist_ok=True)

    owner = get_owner(key_dir)
    if owner is None:
        set_owner(key_dir, email)
    elif owner != email:
        return None, "Forbidden: you do not own this key"

    version = get_next_version(key_dir)
    ext = guess_extension_from_content_type(content_type)
    filename = f"v{version}{ext}" if ext else f"v{version}"
    version_path = os.path.join(versions_dir, filename)

    if isinstance(value, bytes):
        with open(version_path, "wb") as f:
            f.write(value)
    else:
        with open(version_path, "w", encoding="utf-8") as f:
            f.write(value)

    meta = {
        "version": version,
        "content_type": content_type or "application/octet-stream",
        "filename": filename,
    }
    with open(get_meta_path(versions_dir, version), "w", encoding="utf-8") as f:
        json.dump(meta, f)

    return version, None


def read_key(key: str, email: str, version: Optional[int] = None) -> Tuple[Optional[bytes], Optional[dict], Optional[str]]:
    key_dir = get_key_dir(key)
    if not os.path.exists(key_dir):
        return None, None, "Key not found"

    owner = get_owner(key_dir)
    if owner != email:
        return None, None, "Forbidden: you do not own this key"

    versions_dir = get_versions_dir(key_dir)
    if not os.path.exists(versions_dir):
        return None, None, "Key not found"

    if version is not None:
        meta = load_meta(versions_dir, version)
        filename = meta.get("filename") or find_version_filename(versions_dir, version)
        if not filename:
            return None, None, "Version not found"

        version_path = os.path.join(versions_dir, filename)
        if not os.path.exists(version_path):
            return None, None, "Version not found"

        with open(version_path, "rb") as f:
            data = f.read()

        if "filename" not in meta:
            meta["filename"] = filename

        return data, meta, None

    latest = get_latest_version_file(key_dir)
    if latest is None:
        return None, None, "No versions found"

    latest_version, filename = latest
    meta = load_meta(versions_dir, latest_version, fallback_filename=filename)

    version_path = os.path.join(versions_dir, filename)
    with open(version_path, "rb") as f:
        data = f.read()

    return data, meta, None


def serve_key(key: str, email: str, version: Optional[int] = None) -> Tuple[Optional[bytes], Optional[str], Optional[str]]:
    data, meta, error = read_key(key, email, version)
    if error:
        return None, None, error
    return data, meta.get("content_type", "application/octet-stream"), None


# =========================
# Response formatting
# =========================

def decode_content_for_json_response(content: bytes):
    try:
        text = content.decode("utf-8")
    except Exception:
        return base64.b64encode(content).decode("utf-8")

    try:
        return json.loads(text)
    except Exception:
        return text


# =========================
# Routes
# =========================

@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "healthy"}), 200


@app.route("/token", methods=["POST"])
def create_token():
    data = safe_json_body()
    if not data or "email" not in data:
        return json_error("email is required", 400)

    email = data["email"]
    if not isinstance(email, str) or "@" not in email or not email.strip():
        return json_error("Invalid email", 400)

    token = generate_token(email.strip())
    return jsonify({
        "token": token,
        "email": email.strip(),
    }), 200


@app.route("/write", methods=["POST"])
@require_token
def write():
    content_type_header = request.content_type or ""

    key = None
    value = ""
    content_type = "application/octet-stream"

    if "application/json" in content_type_header:
        data = safe_json_body()
        if not data or "key" not in data:
            return json_error("key is required", 400)

        key = data["key"]
        value = data.get("value", "")
        content_type = data.get("content_type", "application/octet-stream")

        if isinstance(value, (dict, list)):
            value = json.dumps(value)
            if content_type == "application/octet-stream":
                content_type = "application/json"

    else:
        key = request.form.get("key")
        if not key:
            return json_error("key is required", 400)

        if "file" in request.files:
            uploaded = request.files["file"]
            value = uploaded.read()
            content_type = uploaded.content_type or "application/octet-stream"
        else:
            value = request.form.get("value", "")
            content_type = request.form.get("content_type", "application/octet-stream")

    if not isinstance(key, str) or not key.strip():
        return json_error("Invalid key", 400)

    version, error = write_key(
        key=key.strip(),
        value=value,
        email=g.auth_email,
        content_type=content_type,
    )
    if error:
        return json_error(error, 403)

    return jsonify({
        "key": key.strip(),
        "version": version,
        "content_type": content_type,
        "message": "Written successfully",
    }), 200


@app.route("/read", methods=["POST"])
@require_token
def read():
    data = safe_json_body()
    if not data or "key" not in data:
        return json_error("key is required", 400)

    key = data["key"]
    version = data.get("version")

    if not isinstance(key, str) or not key.strip():
        return json_error("Invalid key", 400)

    content, meta, error = read_key(key.strip(), g.auth_email, version)
    if error:
        return json_error(error, 403 if "Forbidden" in error else 404)

    value = decode_content_for_json_response(content)

    return jsonify({
        "key": key.strip(),
        "value": value,
        "version": meta.get("version"),
        "content_type": meta.get("content_type", "application/octet-stream"),
        "filename": meta.get("filename"),
    }), 200


@app.route("/serve", methods=["POST"])
@require_token
def serve():
    data = safe_json_body()
    if not data or "key" not in data:
        return json_error("key is required", 400)

    key = data["key"]
    version = data.get("version")

    if not isinstance(key, str) or not key.strip():
        return json_error("Invalid key", 400)

    content, content_type, error = serve_key(key.strip(), g.auth_email, version)
    if error:
        return json_error(error, 403 if "Forbidden" in error else 404)

    return Response(content, mimetype=content_type)


if __name__ == "__main__":
    ensure_storage_base()
    app.run(host="0.0.0.0", port=Config.PORT)
