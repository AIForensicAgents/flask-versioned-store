import hashlib
import json
import os
import time
import mimetypes


def _get_key_dir(base_dir, key):
    """Compute the 3-level directory structure from the SHA256 hash of the key."""
    key_hash = hashlib.sha256(key.encode('utf-8')).hexdigest()
    level1 = key_hash[0:2]
    level2 = key_hash[2:4]
    level3 = key_hash[4:6]
    return os.path.join(base_dir, level1, level2, level3, key_hash)


def _check_owner(key_dir, email):
    """Check owner.json in the key directory. Returns True if owner matches or no owner exists yet.
    Raises PermissionError if owner doesn't match."""
    owner_path = os.path.join(key_dir, 'owner.json')
    if os.path.exists(owner_path):
        with open(owner_path, 'r', encoding='utf-8') as f:
            owner_data = json.load(f)
        if owner_data.get('email') != email:
            raise PermissionError(
                f"Permission denied: key is owned by '{owner_data.get('email')}', "
                f"not '{email}'"
            )
        return True
    return False


def _set_owner(key_dir, email):
    """Write owner.json to claim ownership of a key directory."""
    owner_path = os.path.join(key_dir, 'owner.json')
    owner_data = {'email': email}
    with open(owner_path, 'w', encoding='utf-8') as f:
        json.dump(owner_data, f, indent=2)


def _get_versions(key_dir):
    """Get sorted list of version files in the key directory."""
    versions = []
    if not os.path.exists(key_dir):
        return versions
    for filename in os.listdir(key_dir):
        if filename.startswith('v') and filename.endswith('.json'):
            try:
                version_num = int(filename[1:].replace('.json', ''))
                versions.append((version_num, filename))
            except ValueError:
                continue
    versions.sort(key=lambda x: x[0])
    return versions


def _get_next_version(key_dir):
    """Get the next version number for a key."""
    versions = _get_versions(key_dir)
    if not versions:
        return 1
    return versions[-1][0] + 1


def _get_latest_version_path(key_dir):
    """Get the file path of the latest version."""
    versions = _get_versions(key_dir)
    if not versions:
        return None
    return os.path.join(key_dir, versions[-1][1])


def write_key(base_dir, key, value, email):
    """Write a versioned value for a key.

    Args:
        base_dir: Base directory for storage
        key: The key name
        value: The value to store (can be any JSON-serializable object)
        email: Email of the user performing the write

    Returns:
        dict: Metadata about the written version including key, version, timestamp, email

    Raises:
        PermissionError: If the key is owned by a different email
    """
    key_dir = _get_key_dir(base_dir, key)

    # Create directory structure if needed
    os.makedirs(key_dir, exist_ok=True)

    # Check ownership
    owner_exists = _check_owner(key_dir, email)

    # If no owner yet, set ownership
    if not owner_exists:
        _set_owner(key_dir, email)

    # Determine next version
    version = _get_next_version(key_dir)
    timestamp = time.time()

    # Build version data
    version_data = {
        'key': key,
        'value': value,
        'version': version,
        'timestamp': timestamp,
        'email': email,
    }

    # Write version file
    version_filename = f'v{version}.json'
    version_path = os.path.join(key_dir, version_filename)

    with open(version_path, 'w', encoding='utf-8') as f:
        json.dump(version_data, f, indent=2)

    return {
        'key': key,
        'version': version,
        'timestamp': timestamp,
        'email': email,
    }


def read_key(base_dir, key, email):
    """Read the latest version of a key.

    Args:
        base_dir: Base directory for storage
        key: The key name
        email: Email of the user performing the read

    Returns:
        dict: The version data including key, value, version, timestamp, email

    Raises:
        KeyError: If the key does not exist
        PermissionError: If the key is owned by a different email
    """
    key_dir = _get_key_dir(base_dir, key)

    if not os.path.exists(key_dir):
        raise KeyError(f"Key not found: '{key}'")

    # Check ownership
    _check_owner(key_dir, email)

    # Get latest version
    latest_path = _get_latest_version_path(key_dir)

    if latest_path is None:
        raise KeyError(f"Key not found: '{key}' (no versions available)")

    with open(latest_path, 'r', encoding='utf-8') as f:
        version_data = json.load(f)

    return version_data


def serve_key(base_dir, key, email):
    """Serve the content of a key's latest version with appropriate content type.

    Args:
        base_dir: Base directory for storage
        key: The key name
        email: Email of the user performing the read

    Returns:
        tuple: (content, content_type) where content is the raw content and
               content_type is the MIME type string

    Raises:
        KeyError: If the key does not exist
        PermissionError: If the key is owned by a different email
    """
    version_data = read_key(base_dir, key, email)
    value = version_data.get('value')

    # Determine content type based on the value and key
    content_type = None

    # Try to guess content type from the key name (treat key as filename)
    guessed_type, _ = mimetypes.guess_type(key)
    if guessed_type:
        content_type = guessed_type

    if isinstance(value, (dict, list)):
        content = json.dumps(value, indent=2)
        if content_type is None:
            content_type = 'application/json'
    elif isinstance(value, str):
        content = value
        if content_type is None:
            # Check if it looks like JSON
            try:
                json.loads(value)
                content_type = 'application/json'
            except (json.JSONDecodeError, TypeError):
                content_type = 'text/plain'
    elif isinstance(value, bytes):
        content = value
        if content_type is None:
            content_type = 'application/octet-stream'
    else:
        content = str(value)
        if content_type is None:
            content_type = 'text/plain'

    return (content, content_type)