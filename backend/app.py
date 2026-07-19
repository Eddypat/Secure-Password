"""
app.py
Flask REST API for the Secure Password-Based Encryption and Decryption System.

Endpoints
---------
POST /api/encrypt          { plaintext, password }        -> { ciphertext }
POST /api/decrypt          { ciphertext, password }       -> { plaintext }
POST /api/strength         { password }                   -> { score, label, feedback }
POST /api/encrypt-file     multipart(file, password)      -> encrypted file download
POST /api/decrypt-file     multipart(file, password)      -> decrypted file download

Run with:  python app.py
Then open: http://127.0.0.1:5000
"""

import io
import os

from flask import Flask, request, jsonify, send_file, send_from_directory

from crypto_engine import (
    encrypt_text,
    decrypt_text,
    encrypt_bytes,
    decrypt_bytes,
    evaluate_password_strength,
    DecryptionError,
)

FRONTEND_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "frontend")

app = Flask(__name__, static_folder=FRONTEND_DIR, static_url_path="")


# ---------------------------------------------------------------------------
# Static front-end routes
# ---------------------------------------------------------------------------
@app.route("/")
def index():
    return send_from_directory(FRONTEND_DIR, "index.html")


# ---------------------------------------------------------------------------
# Text encryption / decryption endpoints
# ---------------------------------------------------------------------------
@app.route("/api/encrypt", methods=["POST"])
def api_encrypt():
    data = request.get_json(silent=True) or {}
    plaintext = data.get("plaintext", "")
    password = data.get("password", "")

    if not password:
        return jsonify({"error": "Password is required"}), 400
    if plaintext == "":
        return jsonify({"error": "Plaintext is required"}), 400

    try:
        ciphertext = encrypt_text(plaintext, password)
    except Exception as exc:
        return jsonify({"error": f"Encryption failed: {exc}"}), 500

    return jsonify({"ciphertext": ciphertext})


@app.route("/api/decrypt", methods=["POST"])
def api_decrypt():
    data = request.get_json(silent=True) or {}
    ciphertext = data.get("ciphertext", "")
    password = data.get("password", "")

    if not password:
        return jsonify({"error": "Password is required"}), 400
    if not ciphertext:
        return jsonify({"error": "Ciphertext is required"}), 400

    try:
        plaintext = decrypt_text(ciphertext, password)
    except DecryptionError as exc:
        return jsonify({"error": str(exc)}), 400
    except Exception as exc:
        return jsonify({"error": f"Decryption failed: {exc}"}), 500

    return jsonify({"plaintext": plaintext})


@app.route("/api/strength", methods=["POST"])
def api_strength():
    data = request.get_json(silent=True) or {}
    password = data.get("password", "")
    result = evaluate_password_strength(password)
    return jsonify(result)


# ---------------------------------------------------------------------------
# File encryption / decryption endpoints
# ---------------------------------------------------------------------------
@app.route("/api/encrypt-file", methods=["POST"])
def api_encrypt_file():
    password = request.form.get("password", "")
    uploaded = request.files.get("file")

    if not password:
        return jsonify({"error": "Password is required"}), 400
    if uploaded is None:
        return jsonify({"error": "A file is required"}), 400

    raw = uploaded.read()
    try:
        package_b64 = encrypt_bytes(raw, password)
    except Exception as exc:
        return jsonify({"error": f"Encryption failed: {exc}"}), 500

    out_name = f"{uploaded.filename}.enc"
    buffer = io.BytesIO(package_b64.encode("utf-8"))
    buffer.seek(0)
    return send_file(
        buffer,
        as_attachment=True,
        download_name=out_name,
        mimetype="application/octet-stream",
    )


@app.route("/api/decrypt-file", methods=["POST"])
def api_decrypt_file():
    password = request.form.get("password", "")
    uploaded = request.files.get("file")

    if not password:
        return jsonify({"error": "Password is required"}), 400
    if uploaded is None:
        return jsonify({"error": "A file is required"}), 400

    package_b64 = uploaded.read().decode("utf-8", errors="strict")
    try:
        raw = decrypt_bytes(package_b64, password)
    except DecryptionError as exc:
        return jsonify({"error": str(exc)}), 400
    except Exception as exc:
        return jsonify({"error": f"Decryption failed: {exc}"}), 500

    out_name = uploaded.filename[:-4] if uploaded.filename.endswith(".enc") else f"decrypted_{uploaded.filename}"
    buffer = io.BytesIO(raw)
    buffer.seek(0)
    return send_file(
        buffer,
        as_attachment=True,
        download_name=out_name,
        mimetype="application/octet-stream",
    )


if __name__ == "__main__":
    app.run(debug=True, host="127.0.0.1", port=5000)
