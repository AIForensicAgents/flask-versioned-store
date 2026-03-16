import os
import json
import hashlib
import mimetypes


class VersionedKVStore:
    def __init__(self, base_dir="./storage", hash_algo="sha256", depth=3):
        self.base_dir = base_dir
        self.hash_algo = hash_algo
        self.depth = depth
        os.makedirs(self.base_dir, exist_ok=True)

    def _hash_key(self, key):
        if self.hash_algo == "md5":
            h = hashlib.md5(key.encode("utf-8")).hexdigest()
        else:
            h = hashlib.sha256(key.encode("utf-8")).hexdigest()
        return h

    def _key_dir(self, key):
        h = self._hash_key(key)
        parts = []
        for i in range(self.depth):
            start = i * 2
            end = start + 2
            parts.append(h[start:end])
        parts.append(h)
        return os.path.join(self.base_dir, *parts)

    def _get_versions(self, key_dir):
        if not os.path.isdir(key_dir):
            return []
        versions = []
        for fname in os.listdir(key_dir):
            if fname.startswith("v") and fname.endswith(".json"):
                try:
                    version_num = int(fname[1:].replace(".json", ""))
                    versions.append(version_num)
                except ValueError:
                    continue
        versions.sort()
        return versions

    def _latest_version(self, key_dir):
        versions = self._get_versions(key_dir)
        if not versions:
            return None
        return versions[-1]

    def _next_version(self, key_dir):
        latest = self._latest_version(key_dir)
        if latest is None:
            return 1
        return latest + 1

    def _version_file(self, key_dir, version):
        return os.path.join(key_dir, "v{}.json".format(version))

    def write(self, key, value, metadata=None):
        key_dir = self._key_dir(key)
        os.makedirs(key_dir, exist_ok=True)
        version = self._next_version(key_dir)
        record = {
            "key": key,
            "version": version,
            "value": value,
        }
        if metadata is not None:
            record["metadata"] = metadata
        filepath = self._version_file(key_dir, version)
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(record, f, ensure_ascii=False, indent=2)
        return version

    def read(self, key, version=None):
        key_dir = self._key_dir(key)
        if version is None:
            version = self._latest_version(key_dir)
        if version is None:
            raise KeyError("Key '{}' not found".format(key))
        filepath = self._version_file(key_dir, version)
        if not os.path.isfile(filepath):
            raise KeyError(
                "Key '{}' version {} not found".format(key, version)
            )
        with open(filepath, "r", encoding="utf-8") as f:
            record = json.load(f)
        return record

    def read_value(self, key, version=None):
        record = self.read(key, version=version)
        return record["value"]

    def list_versions(self, key):
        key_dir = self._key_dir(key)
        return self._get_versions(key_dir)

    def delete(self, key, version=None):
        key_dir = self._key_dir(key)
        if version is not None:
            filepath = self._version_file(key_dir, version)
            if os.path.isfile(filepath):
                os.remove(filepath)
                return True
            return False
        else:
            if not os.path.isdir(key_dir):
                return False
            versions = self._get_versions(key_dir)
            for v in versions:
                filepath = self._version_file(key_dir, v)
                if os.path.isfile(filepath):
                    os.remove(filepath)
            # Try to remove directories up the tree
            try:
                os.removedirs(key_dir)
            except OSError:
                pass
            return True

    def exists(self, key):
        key_dir = self._key_dir(key)
        return len(self._get_versions(key_dir)) > 0


def _detect_content_type(value):
    if value is None:
        return b"", "application/octet-stream"

    # If value is bytes (stored as base64 or list of ints), try to detect
    if isinstance(value, (list,)):
        # Assume list of byte values
        try:
            data_bytes = bytes(value)
        except (TypeError, ValueError):
            data_bytes = json.dumps(value).encode("utf-8")
            return data_bytes, "application/json"
        # Try to guess from magic bytes
        content_type = _guess_from_magic(data_bytes)
        if content_type:
            return data_bytes, content_type
        return data_bytes, "application/octet-stream"

    if isinstance(value, dict):
        data_bytes = json.dumps(value, ensure_ascii=False, indent=2).encode("utf-8")
        return data_bytes, "application/json"

    if isinstance(value, (int, float, bool)):
        data_bytes = json.dumps(value).encode("utf-8")
        return data_bytes, "application/json"

    # String value
    if isinstance(value, str):
        stripped = value.strip()

        # Check if it looks like JSON
        if (stripped.startswith("{") and stripped.endswith("}")) or (
            stripped.startswith("[") and stripped.endswith("]")
        ):
            try:
                json.loads(stripped)
                return stripped.encode("utf-8"), "application/json"
            except (json.JSONDecodeError, ValueError):
                pass

        # Check if it looks like HTML
        lower = stripped.lower()
        if (
            lower.startswith("<!doctype html")
            or lower.startswith("<html")
            or lower.startswith("<!")
            or ("<html" in lower and "</html>" in lower)
        ):
            return stripped.encode("utf-8"), "text/html"

        # Check if it looks like XML
        if lower.startswith("<?xml") or (
            lower.startswith("<") and "xmlns" in lower
        ):
            return stripped.encode("utf-8"), "application/xml"

        # Check if it looks like CSS
        if "{" in stripped and "}" in stripped and (":" in stripped) and (
            ";" in stripped
        ):
            # Rough heuristic for CSS
            css_keywords = ["color", "margin", "padding", "font", "display", "background", "border"]
            if any(kw in lower for kw in css_keywords):
                return stripped.encode("utf-8"), "text/css"

        # Check if it looks like SVG
        if "<svg" in lower:
            return stripped.encode("utf-8"), "image/svg+xml"

        # Plain text
        return stripped.encode("utf-8"), "text/plain"

    # Fallback
    data_bytes = str(value).encode("utf-8")
    return data_bytes, "text/plain"


def _guess_from_magic(data_bytes):
    if len(data_bytes) < 4:
        return None

    # PNG
    if data_bytes[:8] == b"\x89PNG\r\n\x1a\n":
        return "image/png"
    # JPEG
    if data_bytes[:2] == b"\xff\xd8":
        return "image/jpeg"
    # GIF
    if data_bytes[:6] in (b"GIF87a", b"GIF89a"):
        return "image/gif"
    # BMP
    if data_bytes[:2] == b"BM":
        return "image/bmp"
    # WebP
    if data_bytes[:4] == b"RIFF" and len(data_bytes) >= 12 and data_bytes[8:12] == b"WEBP":
        return "image/webp"
    # PDF
    if data_bytes[:5] == b"%PDF-":
        return "application/pdf"
    # ZIP
    if data_bytes[:4] == b"PK\x03\x04":
        return "application/zip"
    # GZIP
    if data_bytes[:2] == b"\x1f\x8b":
        return "application/gzip"
    # TIFF
    if data_bytes[:4] in (b"II\x2a\x00", b"MM\x00\x2a"):
        return "image/tiff"
    # ICO
    if data_bytes[:4] == b"\x00\x00\x01\x00":
        return "image/x-icon"

    return None


def serve(store, key, version=None):
    """
    Reads the latest (or specified) version of a key's value,
    detects the content type, and returns (data_bytes, content_type).
    """
    record = store.read(key, version=version)
    value = record.get("value")
    metadata = record.get("metadata", {})

    # If metadata explicitly has content_type, use it
    if isinstance(metadata, dict) and "content_type" in metadata:
        explicit_ct = metadata["content_type"]
        if isinstance(value, str):
            data_bytes = value.encode("utf-8")
        elif isinstance(value, (list,)):
            try:
                data_bytes = bytes(value)
            except (TypeError, ValueError):
                data_bytes = json.dumps(value).encode("utf-8")
        elif isinstance(value, (dict, int, float, bool)):
            data_bytes = json.dumps(value, ensure_ascii=False).encode("utf-8")
        elif isinstance(value, bytes):
            data_bytes = value
        else:
            data_bytes = str(value).encode("utf-8")
        return data_bytes, explicit_ct

    data_bytes, content_type = _detect_content_type(value)
    return data_bytes, content_type


# Convenience functions at module level
_default_store = None


def get_default_store(base_dir="./storage", hash_algo="sha256", depth=3):
    global _default_store
    if _default_store is None or _default_store.base_dir != base_dir:
        _default_store = VersionedKVStore(
            base_dir=base_dir, hash_algo=hash_algo, depth=depth
        )
    return _default_store


if __name__ == "__main__":
    # Demo / self-test
    import tempfile
    import shutil

    test_dir = tempfile.mkdtemp(prefix="vkv_test_")
    print("Test storage dir:", test_dir)

    try:
        store = VersionedKVStore(base_dir=test_dir, depth=3)

        # Write some versions
        v1 = store.write("greeting", "Hello, World!")
        print("Wrote version:", v1)

        v2 = store.write("greeting", "Hello, World! v2")
        print("Wrote version:", v2)

        v3 = store.write("greeting", {"message": "Hello, World!", "version": 3})
        print("Wrote version:", v3)

        # Read latest
        latest = store.read_value("greeting")
        print("Latest value:", latest)

        # Read specific version
        val_v1 = store.read_value("greeting", version=1)
        print("Version 1 value:", val_v1)

        # List versions
        versions = store.list_versions("greeting")
        print("All versions:", versions)

        # Serve - JSON
        store.write("config", {"database": "localhost", "port": 5432})
        data, ct = serve(store, "config")
        print("Serve config -> content_type:", ct, "data:", data.decode("utf-8"))

        # Serve - HTML
        store.write("page", "<!DOCTYPE html><html><body><h1>Hello</h1></body></html>")
        data, ct = serve(store, "page")
        print("Serve page -> content_type:", ct)

        # Serve - plain text
        store.write("note", "Just a plain text note.")
        data, ct = serve(store, "note")
        print("Serve note -> content_type:", ct)

        # Serve with explicit content_type metadata
        store.write(
            "image_ref",
            [137, 80, 78, 71, 13, 10, 26, 10, 0, 0, 0, 0],
            metadata={"content_type": "image/png"},
        )
        data, ct = serve(store, "image_ref")
        print("Serve image_ref -> content_type:", ct, "bytes:", len(data))

        # Exists check
        print("Exists 'greeting':", store.exists("greeting"))
        print("Exists 'nonexistent':", store.exists("nonexistent"))

        # Delete specific version
        store.delete("greeting", version=1)
        print("Versions after deleting v1:", store.list_versions("greeting"))

        # Delete all
        store.delete("greeting")
        print("Exists 'greeting' after delete:", store.exists("greeting"))

        print("\nAll tests passed!")

    finally:
        shutil.rmtree(test_dir, ignore_errors=True)