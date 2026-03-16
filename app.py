from flask import Flask, request, jsonify

from config import Config
from auth import create_token, require_token
from storage import write_value, read_value, serve_value

app = Flask(__name__)
app.config.from_object(Config)


@app.route("/token", methods=["POST"])
def token_endpoint():
    data = request.get_json(force=True)
    email = data.get("email")
    if not email:
        return jsonify({"error": "email is required"}), 400
    token = create_token(email)
    return jsonify({"token": token})


@app.route("/write", methods=["POST"])
@require_token
def write_endpoint():
    data = request.get_json(force=True)
    key = data.get("key")
    value = data.get("value")
    if key is None or value is None:
        return jsonify({"error": "key and value are required"}), 400
    result = write_value(key, value)
    return jsonify(result)


@app.route("/read", methods=["POST"])
@require_token
def read_endpoint():
    data = request.get_json(force=True)
    key = data.get("key")
    if key is None:
        return jsonify({"error": "key is required"}), 400
    result = read_value(key)
    if result is None:
        return jsonify({"error": "key not found"}), 404
    return jsonify({"key": key, "value": result})


@app.route("/serve", methods=["POST"])
@require_token
def serve_endpoint():
    data = request.get_json(force=True)
    key = data.get("key")
    if key is None:
        return jsonify({"error": "key is required"}), 400
    response = serve_value(key)
    if response is None:
        return jsonify({"error": "key not found"}), 404
    return response


if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=5000,
        debug=True,
        ssl_context=(Config.CERT_FILE, Config.KEY_FILE),
    )