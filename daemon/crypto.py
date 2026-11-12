"""AES-256-GCM payload sealing; optional ``cryptography`` dependency.

Sealed format: b"SR1" | 12-byte nonce | ciphertext + 16-byte tag.
"""

import hashlib
import hmac
import os

try:  # pragma: no cover - exercised only when the optional package exists
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF

    _CRYPTOGRAPHY_ERROR = None
except ImportError as exc:  # pragma: no cover - depends on the host
    AESGCM = None
    HKDF = None
    hashes = None
    _CRYPTOGRAPHY_ERROR = exc

PREFIX = b"SR1"
NONCE_BYTES = 12
KEY_BYTES = 32
DEFAULT_SALT = b"streaprous-chat-v1"
DEFAULT_INFO = b"payload-encryption"


def available():
    """Return ``True`` when AES-GCM support is importable."""
    return AESGCM is not None


def derive_key(secret, *, salt=DEFAULT_SALT, info=DEFAULT_INFO):
    """Derive a 32-byte key from a shared secret.

    HKDF-SHA256 is used when ``cryptography`` is installed; otherwise the
    deterministic HMAC-SHA256 construction still yields a distinct key per
    salt/info pair.
    """
    if isinstance(secret, str):
        secret = secret.encode("utf-8")
    if not isinstance(secret, (bytes, bytearray)) or not secret:
        raise ValueError("secret must be non-empty bytes")
    if HKDF is not None:
        return HKDF(
            algorithm=hashes.SHA256(),
            length=KEY_BYTES,
            salt=salt,
            info=info,
        ).derive(bytes(secret))
    return hmac.new(bytes(secret), bytes(salt) + bytes(info), hashlib.sha256).digest()


class PayloadCipher:
    """Seal and open payloads with AES-256-GCM."""

    def __init__(self, key):
        key = bytes(key)
        if len(key) != KEY_BYTES:
            raise ValueError(f"key must be {KEY_BYTES} bytes")
        if AESGCM is None:
            raise RuntimeError(
                "AES-GCM support requires the 'cryptography' package"
            ) from _CRYPTOGRAPHY_ERROR
        self._aead = AESGCM(key)

    @classmethod
    def from_secret(cls, secret, **kwargs):
        return cls(derive_key(secret, **kwargs))

    def seal(self, plaintext, aad=b""):
        nonce = os.urandom(NONCE_BYTES)
        return PREFIX + nonce + self._aead.encrypt(nonce, bytes(plaintext), aad)

    def open(self, blob, aad=b""):
        blob = bytes(blob)
        if not blob.startswith(PREFIX):
            raise ValueError("payload is not an SR1 sealed blob")
        body = blob[len(PREFIX):]
        if len(body) <= NONCE_BYTES:
            raise ValueError("sealed payload is truncated")
        nonce, ciphertext = body[:NONCE_BYTES], body[NONCE_BYTES:]
        try:
            return self._aead.decrypt(nonce, ciphertext, aad)
        except Exception as exc:  # cryptography raises InvalidTag
            raise ValueError("payload failed authentication") from exc


__all__ = [
    "KEY_BYTES",
    "NONCE_BYTES",
    "PREFIX",
    "PayloadCipher",
    "available",
    "derive_key",
]
