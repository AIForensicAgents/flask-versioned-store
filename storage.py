"""Versioned filesystem storage engine.

Keys are mapped to a three-level directory hierarchy derived from the
SHA-256 hash of the key name.  Each key directory contains an
``owner.json`` file (first writer wins) and a ``versions/`` folder with
individually numbered version files plus accompanying metadata.
"""

import hashlib
import json
import mimetypes
import os
from typing import Any


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _get_key_hash(key: str) -> str:
    """Return the hex SHA-256 digest of *key*."""
    return hashlib.sha256(key.encode("utf-8")).hexdigest()


def _get_key_dir(base_dir: str, key: str) -> str:
    """Compute the three-level directory path for *key*."""
    h = _get_key_hash(key)
    return os.path.join(base_dir, h[:2], h[2:4], h[4:6], h)


def _get_owner(key_dir: str) -> str | None:
    """Read the owner email from *key_dir*/owner.json, or None."""
    owner_file = os.path.join(key_dir, "owner.json")
    if os.path.exists(owner_file):
        with open(owner_file, "r", encoding="utf-8") as f:
            return json.load(f).get("email")
    return None


def _set_owner(key_dir: str, email: str) -> None:
    """Persist *email* as the owner of *key_dir*."""
    owner_file = os.path.join(key_dir, "owner.json")
    with open(owner_file, "w", encoding="utf-8") as f:
        json.dump({"email": email}, f, indent=2)


def _check_owner(key_dir: str, email: str) -> bool:
    """Verify ownership.  Returns True if *email* matches the owner.

    Returns False when no owner has been set yet.
    Raises ``PermissionError`` if the key belongs to someone else.
    """
    owner = _get_owner(key_dir)
    if owner is None:
        return False
    if owner != email:
        raise PermissionError(f"Forbidden: key is owned by '{owner}', not '{email}'")
    return True


def _list_versions(versions_dir: str) -> list[tuple[int, str]]:
    """Return a sorted list of ``(version_number, filename)`` tuples."""
    versions: list[tuple[int, str]] = []
    if not os.path.exists(versions_dir):
        return versions
    for fname in os.listdir(versions_dir):
        if fname.endswith(".meta.json"):
            continue
        if not fname.startswith("v"):
            continue
        try:
            v = int(fname.split(".")[0].removeprefix("v"))
            versions.append((v, fname))
        except (ValueError, IndexError):
            continue
    versions.sort(key=lambda x: x[0])
    return versions


def _get_next_version(versions_dir: str) -> int:
    """Return the next version number to use."""
    versions = _list_versions(versions_dir)
    if not versions:
        return 1
    return versions[-1][0] + 1


def _get_latest_version(versions_dir: str) -> tuple[int, str] | None:
    """Return ``(version_number, filename)`` for the latest version, or None."""
    versions = _list_versions(versions_dir)
    return versions[-1] if versions else None


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def write_key(
    base_dir: str,
    key: str,
    value: str | bytes,
    email: str,
    content_type: str | None = None,
) -> tuple[int | None, str | None]:
    """Write a new version of *key*.

    Returns ``(version, None)`` on success or ``(None, error_message)`` on
    failure (e.g. ownership mismatch).
    """
    key_dir = _get_key_dir(base_dir, key)
    versions_dir = os.path.join(key_dir, "versions")
    os.makedirs(versions_dir, exist_ok=True)

    try:
        owner_exists = _check_owner(key_dir, email)
    except PermissionError as exc:
        return None, str(exc)

    if not owner_exists:
        _set_owner(key_dir, email)

    version = _get_next_version(versions_dir)

    # Determine file extension from content type
    ext = ""
    if content_type:
        guessed = mimetypes.guess_extension(content_type)
        if guessed:
            ext = guessed

    version_filename = f"v{version}{ext}" if ext else f"v{version}"
    version_path = os.path.join(versions_dir, version_filename)

    # Write content
    if isinstance(value, bytes):
        with open(version_path, "wb") as f:
            f.write(value)
    else:
        with open(version_path, "w", encoding="utf-8") as f:
            f.write(value)

    # Write metadata sidecar
    meta = {
        "version": version,
        "content_type": content_type or "application/octet-stream",
        "filename": version_filename,
    }
    meta_path = os.path.join(versions_dir, f"v{version}.meta.json")
    with open(meta_path, "w", encoding="utf-8") as f:
        json.dump(meta, f, indent=2)

    return version, None


def read_key(
    base_dir: str,
    key: str,
    email: str,
    version: int | None = None,
) -> tuple[bytes | None, dict | None, str | None]:
    """Read a version of *key* (latest when *version* is None).

    Returns ``(data, meta_dict, None)`` on success or
    ``(None, None, error_message)`` on failure.
    """
    key_dir = _get_key_dir(base_dir, key)

    if not os.path.exists(key_dir):
        return None, None, "Key not found"

    try:
        _check_owner(key_dir, email)
    except PermissionError as exc:
        return None, None, str(exc)

    versions_dir = os.path.join(key_dir, "versions")
    if not os.path.exists(versions_dir):
        return None, None, "Key not found"

    if version is not None:
        # --- specific version ---
        meta_path = os.path.join(versions_dir, f"v{version}.meta.json")
        if os.path.exists(meta_path):
            with open(meta_path, "r", encoding="utf-8") as f:
                meta = json.load(f)
            version_path = os.path.join(versions_dir, meta["filename"])
        else:
            # Fallback: find by prefix
            found = None
            for fname in os.listdir(versions_dir):
                if fname.startswith(f"v{version}") and not fname.endswith(".meta.json"):
                    found = fname
                    break
            if not found:
                return None, None, "Version not found"
            version_path = os.path.join(versions_dir, found)
            meta = {"version": version, "content_type": "application/octet-stream"}

        if not os.path.exists(version_path):
            return None, None, "Version not found"
    else:
        # --- latest version ---
        latest = _get_latest_version(versions_dir)
        if latest is None:
            return None, None, "No versions found"
        v_num, v_fname = latest
        meta_path = os.path.join(versions_dir, f"v{v_num}.meta.json")
        if os.path.exists(meta_path):
            with open(meta_path, "r", encoding="utf-8") as f:
                meta = json.load(f)
        else:
            meta = {"version": v_num, "content_type": "application/octet-stream"}
        version_path = os.path.join(versions_dir, v_fname)

    with open(version_path, "rb") as f:
        data = f.read()

    return data, meta, None


def serve_key(
    base_dir: str,
    key: str,
    email: str,
    version: int | None = None,
) -> tuple[bytes | None, str | None, str | None]:
    """Convenience wrapper that returns ``(data, content_type, error)``."""
    data, meta, error = read_key(base_dir, key, email, version)
    if error:
        return None, None, error
    content_type = meta.get("content_type", "application/octet-stream")
    return data, content_type, None
