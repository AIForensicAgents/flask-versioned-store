import os
import json
import hashlib
import mimetypes
from flask import Flask, request, jsonify, Response
from functools import wraps

# --- config.py functionality ---
class Config:
    STORAGE_BASE_DIR = os.environ.get('STORAGE_BASE_DIR', '/data/store')
    PORT = int(os.environ.get('PORT', 8080))
    SECRET_KEY = os.environ.get('SECRET_KEY', 'default-secret-key-change-me')

# --- auth.py functionality ---
import hmac
import time
import base64

def generate_token(email):
    timestamp = str(int(time.time()))
    payload = f"{email}:{timestamp}"
    signature = hmac.new(
        Config.SECRET_KEY.encode('utf-8'),
        payload.encode('utf-8'),
        hashlib.sha256
    ).hexdigest()
    token_data = f"{payload}:{signature}"
    token = base64.urlsafe_b64encode(token_data.encode('utf-8')).decode('utf-8')
    return token

def validate_token(token):
    try:
        token_data = base64.urlsafe_b64decode(token.encode('utf-8')).decode('utf-8')
        parts = token_data.rsplit(':', 2)
        if len(parts) != 3:
            return False
        email, timestamp, signature = parts
        payload = f"{email}:{timestamp}"
        expected_signature = hmac.new(
            Config.SECRET_KEY.encode('utf-8'),
            payload.encode('utf-8'),
            hashlib.sha256
        ).hexdigest()
        return hmac.compare_digest(signature, expected_signature)
    except Exception:
        return False

def get_email_from_token(token):
    try:
        token_data = base64.urlsafe_b64decode(token.encode('utf-8')).decode('utf-8')
        parts = token_data.rsplit(':', 2)
        if len(parts) != 3:
            return None
        return parts[0]
    except Exception:
        return None

def require_token(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get('Authorization', '')
        if not auth_header.startswith('Bearer '):
            return jsonify({'error': 'Missing or invalid Authorization header'}), 401
        token = auth_header[7:]
        if not validate_token(token):
            return jsonify({'error': 'Invalid token'}), 401
        email = get_email_from_token(token)
        if not email:
            return jsonify({'error': 'Could not extract email from token'}), 401
        request.email = email
        request.token = token
        return f(*args, **kwargs)
    return decorated

# --- storage.py functionality ---

def _get_key_hash(key):
    return hashlib.sha256(key.encode('utf-8')).hexdigest()

def _get_key_dir(key):
    h = _get_key_hash(key)
    level1 = h[:2]
    level2 = h[2:4]
    level3 = h[4:6]
    key_dir = os.path.join(Config.STORAGE_BASE_DIR, level1, level2, level3, h)
    return key_dir

def _get_owner(key_dir):
    owner_file = os.path.join(key_dir, 'owner.json')
    if os.path.exists(owner_file):
        with open(owner_file, 'r') as f:
            data = json.load(f)
        return data.get('email')
    return None

def _set_owner(key_dir, email):
    owner_file = os.path.join(key_dir, 'owner.json')
    with open(owner_file, 'w') as f:
        json.dump({'email': email}, f)

def _get_next_version(key_dir):
    versions_dir = os.path.join(key_dir, 'versions')
    if not os.path.exists(versions_dir):
        return 1
    existing = []
    for fname in os.listdir(versions_dir):
        try:
            v = int(fname.split('.')[0].replace('v', ''))
            existing.append(v)
        except (ValueError, IndexError):
            continue
    if not existing:
        return 1
    return max(existing) + 1

def _get_latest_version(key_dir):
    versions_dir = os.path.join(key_dir, 'versions')
    if not os.path.exists(versions_dir):
        return None
    existing = []
    for fname in os.listdir(versions_dir):
        try:
            v = int(fname.split('.')[0].replace('v', ''))
            existing.append((v, fname))
        except (ValueError, IndexError):
            continue
    if not existing:
        return None
    existing.sort(key=lambda x: x[0], reverse=True)
    return existing[0]

def write_key(key, value, email, content_type=None):
    key_dir = _get_key_dir(key)
    versions_dir = os.path.join(key_dir, 'versions')
    os.makedirs(versions_dir, exist_ok=True)

    owner = _get_owner(key_dir)
    if owner is None:
        _set_owner(key_dir, email)
    elif owner != email:
        return None, 'Forbidden: you do not own this key'

    version = _get_next_version(key_dir)

    # Determine extension from content_type
    ext = ''
    if content_type:
        guessed = mimetypes.guess_extension(content_type)
        if guessed:
            ext = guessed

    version_filename = f"v{version}{ext}" if ext else f"v{version}"
    version_path = os.path.join(versions_dir, version_filename)

    if isinstance(value, bytes):
        with open(version_path, 'wb') as f:
            f.write(value)
    else:
        with open(version_path, 'w') as f:
            f.write(value)

    # Store metadata
    meta_path = os.path.join(versions_dir, f"v{version}.meta.json")
    meta = {
        'version': version,
        'content_type': content_type or 'application/octet-stream',
        'filename': version_filename
    }
    with open(meta_path, 'w') as f:
        json.dump(meta, f)

    return version, None

def read_key(key, email, version=None):
    key_dir = _get_key_dir(key)

    if not os.path.exists(key_dir):
        return None, None, 'Key not found'

    owner = _get_owner(key_dir)
    if owner != email:
        return None, None, 'Forbidden: you do not own this key'

    versions_dir = os.path.join(key_dir, 'versions')
    if not os.path.exists(versions_dir):
        return None, None, 'Key not found'

    if version is not None:
        # Find specific version
        meta_path = os.path.join(versions_dir, f"v{version}.meta.json")
        if os.path.exists(meta_path):
            with open(meta_path, 'r') as f:
                meta = json.load(f)
            version_path = os.path.join(versions_dir, meta['filename'])
        else:
            # Try finding version file without meta
            found = None
            for fname in os.listdir(versions_dir):
                if fname.startswith(f"v{version}") and not fname.endswith('.meta.json'):
                    found = fname
                    break
            if not found:
                return None, None, 'Version not found'
            version_path = os.path.join(versions_dir, found)
            meta = {'version': version, 'content_type': 'application/octet-stream'}

        if not os.path.exists(version_path):
            return None, None, 'Version not found'

        with open(version_path, 'rb') as f:
            data = f.read()

        return data, meta, None
    else:
        # Get latest version
        latest = _get_latest_version(key_dir)
        if latest is None:
            return None, None, 'No versions found'

        v_num, v_fname = latest
        meta_path = os.path.join(versions_dir, f"v{v_num}.meta.json")
        if os.path.exists(meta_path):
            with open(meta_path, 'r') as f:
                meta = json.load(f)
        else:
            meta = {'version': v_num, 'content_type': 'application/octet-stream'}

        version_path = os.path.join(versions_dir, v_fname)
        with open(version_path, 'rb') as f:
            data = f.read()

        return data, meta, None

def serve_key(key, email, version=None):
    data, meta, error = read_key(key, email, version)
    if error:
        return None, None, error
    content_type = meta.get('content_type', 'application/octet-stream')
    return data, content_type, None

# --- Flask App ---

app = Flask(__name__)
app.config.from_object(Config)

@app.route('/health', methods=['GET'])
def health():
    return jsonify({'status': 'healthy'}), 200

@app.route('/token', methods=['POST'])
def create_token():
    data = request.get_json()
    if not data or 'email' not in data:
        return jsonify({'error': 'email is required'}), 400

    email = data['email']
    if not email or not isinstance(email, str) or '@' not in email:
        return jsonify({'error': 'Invalid email'}), 400

    token = generate_token(email)
    return jsonify({'token': token, 'email': email}), 200

@app.route('/write', methods=['POST'])
@require_token
def write():
    content_type_header = request.content_type or ''

    if 'application/json' in content_type_header:
        data = request.get_json()
        if not data or 'key' not in data:
            return jsonify({'error': 'key is required'}), 400

        key = data['key']
        value = data.get('value', '')
        ct = data.get('content_type', 'application/octet-stream')

        if isinstance(value, (dict, list)):
            value = json.dumps(value)
            if ct == 'application/octet-stream':
                ct = 'application/json'
    else:
        key = request.form.get('key')
        if not key:
            return jsonify({'error': 'key is required'}), 400

        if 'file' in request.files:
            file = request.files['file']
            value = file.read()
            ct = file.content_type or 'application/octet-stream'
        else:
            value = request.form.get('value', '')
            ct = request.form.get('content_type', 'application/octet-stream')

    email = request.email
    version, error = write_key(key, value, email, content_type=ct)

    if error:
        return jsonify({'error': error}), 403

    return jsonify({
        'key': key,
        'version': version,
        'message': 'Written successfully'
    }), 200

@app.route('/read', methods=['POST'])
@require_token
def read():
    data = request.get_json()
    if not data or 'key' not in data:
        return jsonify({'error': 'key is required'}), 400

    key = data['key']
    version = data.get('version')
    email = request.email

    content, meta, error = read_key(key, email, version)

    if error:
        if 'Forbidden' in error:
            return jsonify({'error': error}), 403
        return jsonify({'error': error}), 404

    # Try to decode as text
    try:
        value = content.decode('utf-8')
        # Try to parse as JSON
        try:
            value = json.loads(value)
        except (json.JSONDecodeError, ValueError):
            pass
    except (UnicodeDecodeError, AttributeError):
        value = base64.b64encode(content).decode('utf-8')

    return jsonify({
        'key': key,
        'value': value,
        'version': meta.get('version'),
        'content_type': meta.get('content_type', 'application/octet-stream')
    }), 200

@app.route('/serve', methods=['POST'])
@require_token
def serve():
    data = request.get_json()
    if not data or 'key' not in data:
        return jsonify({'error': 'key is required'}), 400

    key = data['key']
    version = data.get('version')
    email = request.email

    content, content_type, error = serve_key(key, email, version)

    if error:
        if 'Forbidden' in error:
            return jsonify({'error': error}), 403
        return jsonify({'error': error}), 404

    return Response(content, mimetype=content_type)

if __name__ == '__main__':
    os.makedirs(Config.STORAGE_BASE_DIR, exist_ok=True)
    app.run(host='0.0.0.0', port=Config.PORT)