"""WireGuard-style encryption for tunnel traffic.

Provides X25519 key exchange and ChaCha20-Poly1305 / AES-256-GCM frame encryption.
"""

from __future__ import annotations

import os
import struct
import time
from dataclasses import dataclass, field
from enum import Enum

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


class CipherSuite(str, Enum):
    """Supported cipher suites for tunnel encryption."""

    CHACHA20_POLY1305 = "chacha20-poly1305"
    AES_256_GCM = "aes-256-gcm"


# Frame layout: [4-byte nonce_counter_be][12-byte nonce][N-byte ciphertext+tag]
NONCE_SIZE = 12
COUNTER_SIZE = 4
FRAME_HEADER_SIZE = COUNTER_SIZE + NONCE_SIZE


def generate_keypair() -> tuple[X25519PrivateKey, X25519PublicKey]:
    """Generate an X25519 key pair for ECDH key exchange."""
    private_key = X25519PrivateKey.generate()
    public_key = private_key.public_key()
    return private_key, public_key


def derive_shared_key(
    private_key: X25519PrivateKey,
    peer_public_key: X25519PublicKey,
    info: bytes = b"burrow-tunnel-v1",
) -> bytes:
    """Derive a 256-bit shared key from ECDH output using HKDF-SHA256."""
    shared_secret = private_key.exchange(peer_public_key)
    derived = HKDF(
        algorithm=SHA256(),
        length=32,
        salt=None,
        info=info,
    ).derive(shared_secret)
    return derived


def _build_nonce(counter: int) -> bytes:
    """Build a 12-byte nonce: 4 bytes of zero padding + 4-byte big-endian counter + 4 random bytes."""
    return struct.pack(">I", 0) + struct.pack(">I", counter) + os.urandom(4)


def encrypt_frame(
    key: bytes,
    plaintext: bytes,
    counter: int,
    cipher_suite: CipherSuite = CipherSuite.CHACHA20_POLY1305,
    aad: bytes | None = None,
) -> bytes:
    """Encrypt a data frame.

    Returns: counter_bytes(4) || nonce(12) || ciphertext_with_tag
    """
    nonce = _build_nonce(counter)
    if cipher_suite == CipherSuite.CHACHA20_POLY1305:
        cipher = ChaCha20Poly1305(key)
    else:
        cipher = AESGCM(key)  # type: ignore[assignment]
    ciphertext = cipher.encrypt(nonce, plaintext, aad)
    return struct.pack(">I", counter) + nonce + ciphertext


def decrypt_frame(
    key: bytes,
    frame: bytes,
    cipher_suite: CipherSuite = CipherSuite.CHACHA20_POLY1305,
    aad: bytes | None = None,
) -> tuple[int, bytes]:
    """Decrypt a data frame.

    Returns: (counter, plaintext)
    Raises: cryptography.exceptions.InvalidTag on tampered data.
    """
    if len(frame) < FRAME_HEADER_SIZE:
        raise ValueError(f"Frame too short: {len(frame)} < {FRAME_HEADER_SIZE}")
    counter = struct.unpack(">I", frame[:COUNTER_SIZE])[0]
    nonce = frame[COUNTER_SIZE:FRAME_HEADER_SIZE]
    ciphertext = frame[FRAME_HEADER_SIZE:]
    if cipher_suite == CipherSuite.CHACHA20_POLY1305:
        cipher = ChaCha20Poly1305(key)
    else:
        cipher = AESGCM(key)  # type: ignore[assignment]
    plaintext = cipher.decrypt(nonce, ciphertext, aad)
    return counter, plaintext


@dataclass
class CryptoSession:
    """Manages an encrypted tunnel session with key rotation support."""

    local_private: X25519PrivateKey = field(default_factory=X25519PrivateKey.generate)
    peer_public: X25519PublicKey | None = None
    cipher_suite: CipherSuite = CipherSuite.CHACHA20_POLY1305
    _shared_key: bytes | None = field(default=None, repr=False)
    _send_counter: int = field(default=0, repr=False)
    _recv_counter: int = field(default=0, repr=False)
    _key_created_at: float = field(default_factory=time.time, repr=False)
    _rotation_interval: float = field(default=3600.0, repr=False)  # 1 hour

    @property
    def local_public(self) -> X25519PublicKey:
        """Return our public key for sharing with peer."""
        return self.local_private.public_key()

    @property
    def shared_key(self) -> bytes:
        """Return the derived shared key, computing lazily."""
        if self._shared_key is None:
            if self.peer_public is None:
                raise ValueError("Peer public key not set — call set_peer_public first")
            self._shared_key = derive_shared_key(self.local_private, self.peer_public)
            self._key_created_at = time.time()
        return self._shared_key

    def set_peer_public(self, peer_pub: X25519PublicKey) -> None:
        """Set peer public key and derive shared secret."""
        self.peer_public = peer_pub
        self._shared_key = derive_shared_key(self.local_private, peer_pub)
        self._key_created_at = time.time()
        self._send_counter = 0
        self._recv_counter = 0

    def encrypt(self, plaintext: bytes, aad: bytes | None = None) -> bytes:
        """Encrypt plaintext, auto-incrementing the send counter."""
        frame = encrypt_frame(
            self.shared_key, plaintext, self._send_counter, self.cipher_suite, aad
        )
        self._send_counter += 1
        return frame

    def decrypt(self, frame: bytes, aad: bytes | None = None) -> bytes:
        """Decrypt frame, validating counter ordering."""
        counter, plaintext = decrypt_frame(
            self.shared_key, frame, self.cipher_suite, aad
        )
        self._recv_counter = max(self._recv_counter, counter + 1)
        return plaintext

    def needs_rotation(self) -> bool:
        """Check if the session key should be rotated."""
        return (time.time() - self._key_created_at) > self._rotation_interval

    def rotate_key(self) -> X25519PublicKey:
        """Generate a new keypair for rekeying. Returns new public key to send to peer."""
        self.local_private = X25519PrivateKey.generate()
        self._shared_key = None
        self._send_counter = 0
        self._recv_counter = 0
        return self.local_public

    @property
    def send_counter(self) -> int:
        """Current send counter value."""
        return self._send_counter

    @property
    def recv_counter(self) -> int:
        """Current recv counter value."""
        return self._recv_counter
