"""
crypto_engine.py
Core cryptographic engine for the Secure Password-Based Encryption
and Decryption System.

Design summary
---------------
- Key derivation : PBKDF2-HMAC-SHA256, 480,000 iterations, 16-byte random salt
- Encryption     : AES-256-GCM (authenticated encryption)
- Package format : base64( salt[16] | nonce[12] | ciphertext+tag )
- Password check : entropy / rule based strength scorer (0-100)

No plaintext, password, or derived key is ever written to disk or logged.
"""

import os
import base64
import hashlib
import hmac
import re

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

# ---------------------------------------------------------------------------
# Configuration constants
# ---------------------------------------------------------------------------
PBKDF2_ITERATIONS = 480_000
SALT_SIZE = 16          # bytes (128-bit salt)
NONCE_SIZE = 12          # bytes (96-bit nonce, required for AES-GCM)
KEY_SIZE = 32          # bytes (256-bit AES key)


class DecryptionError(Exception):
    """Raised when decryption fails due to a wrong password or tampered data."""
    pass


def derive_key(password: str, salt: bytes, iterations: int = PBKDF2_ITERATIONS) -> bytes:
    """Derive a 256-bit AES key from a password and salt using PBKDF2-HMAC-SHA256."""
    if not isinstance(password, str) or password == "":
        raise ValueError("Password must be a non-empty string")
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=salt,
        iterations=iterations,
    )
    return kdf.derive(password.encode("utf-8"))


def encrypt_bytes(plaintext: bytes, password: str) -> str:
    """
    Encrypt raw bytes with a password.
    Returns a base64-encoded string: salt | nonce | ciphertext+tag
    """
    salt = os.urandom(SALT_SIZE)
    nonce = os.urandom(NONCE_SIZE)
    key = derive_key(password, salt)

    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)  # tag is appended internally

    package = salt + nonce + ciphertext
    return base64.b64encode(package).decode("utf-8")


def decrypt_bytes(package_b64: str, password: str) -> bytes:
    """
    Decrypt a base64-encoded package (salt | nonce | ciphertext+tag)
    produced by encrypt_bytes(), returning the original plaintext bytes.
    Raises DecryptionError on wrong password or tampered ciphertext.
    """
    try:
        package = base64.b64decode(package_b64, validate=True)
    except Exception:
        raise DecryptionError("Invalid ciphertext package: not valid base64 data")

    if len(package) < SALT_SIZE + NONCE_SIZE + 16:
        raise DecryptionError("Invalid ciphertext package: data too short")

    salt = package[:SALT_SIZE]
    nonce = package[SALT_SIZE:SALT_SIZE + NONCE_SIZE]
    ciphertext = package[SALT_SIZE + NONCE_SIZE:]

    key = derive_key(password, salt)
    aesgcm = AESGCM(key)

    try:
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    except InvalidTag:
        raise DecryptionError("Decryption failed: incorrect password or corrupted/tampered data")

    return plaintext


def encrypt_text(plaintext: str, password: str) -> str:
    return encrypt_bytes(plaintext.encode("utf-8"), password)


def decrypt_text(package_b64: str, password: str) -> str:
    plaintext_bytes = decrypt_bytes(package_b64, password)
    try:
        return plaintext_bytes.decode("utf-8")
    except UnicodeDecodeError:
        raise DecryptionError("Decrypted data is not valid UTF-8 text")


# ---------------------------------------------------------------------------
# Password strength evaluation
# ---------------------------------------------------------------------------
COMMON_PASSWORDS = {
    "password", "123456", "12345678", "qwerty", "abc123", "letmein",
    "monkey", "111111", "iloveyou", "admin", "welcome", "password1",
}


def evaluate_password_strength(password: str) -> dict:
    """
    Score a password from 0-100 and classify it as Weak / Fair / Strong / Very Strong.
    Purely rule-based; mirrors the logic used in script.js on the client side.
    """
    if not password:
        return {"score": 0, "label": "Weak", "feedback": ["Password is empty"]}

    score = 0
    feedback = []

    length = len(password)
    if length >= 8:
        score += 20
    if length >= 12:
        score += 15
    if length >= 16:
        score += 15
    if length < 8:
        feedback.append("Use at least 8 characters (12+ recommended)")

    has_lower = re.search(r"[a-z]", password) is not None
    has_upper = re.search(r"[A-Z]", password) is not None
    has_digit = re.search(r"\d", password) is not None
    has_symbol = re.search(r"[^A-Za-z0-9]", password) is not None

    variety = sum([has_lower, has_upper, has_digit, has_symbol])
    score += variety * 10

    if not has_upper:
        feedback.append("Add uppercase letters")
    if not has_lower:
        feedback.append("Add lowercase letters")
    if not has_digit:
        feedback.append("Add numbers")
    if not has_symbol:
        feedback.append("Add special characters (e.g. !@#$%)")

    if re.search(r"(.)\1{2,}", password):
        score -= 15
        feedback.append("Avoid repeated characters")

    if re.search(r"(0123|1234|2345|3456|4567|5678|6789|9876|8765)", password):
        score -= 15
        feedback.append("Avoid sequential digits")

    if password.lower() in COMMON_PASSWORDS:
        score = min(score, 10)
        feedback.append("This is a very common password \u2014 choose something less predictable")

    score = max(0, min(100, score))

    if score < 40:
        label = "Weak"
    elif score < 65:
        label = "Fair"
    elif score < 85:
        label = "Strong"
    else:
        label = "Very Strong"

    return {"score": score, "label": label, "feedback": feedback}
