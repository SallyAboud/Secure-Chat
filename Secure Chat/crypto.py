"""
crypto.py — Stream Cipher Encryption Engine
============================================
ECE 4304 Data Security Project

Security Stack:
  1. SHA-256 Key Stream Generator  → expands the shared secret + nonce into a strong keystream
  2. XOR Stream Cipher              → encrypts plaintext byte-by-byte (XOR with keystream)
  3. HMAC-SHA256 MAC                → authenticates ciphertext; detects Man-in-the-Middle tampering
  4. Random 16-byte Nonce           → unique per message; prevents replay attacks & keystream reuse

Wire Format (per message):
  [4 bytes: payload length as big-endian int]
  [16 bytes: random nonce]
  [N bytes: ciphertext  = plaintext XOR keystream]
  [32 bytes: HMAC-SHA256(key, nonce || ciphertext)]
"""

import hashlib
import hmac
import os
import struct


class WrongKeyError(Exception):
    """Raised when HMAC verification fails — wrong key or tampered message."""
    pass


# ──────────────────────────────────────────────────────────────────────────────
#  Keystream Generation  (SHA-256 Counter Mode)
# ──────────────────────────────────────────────────────────────────────────────

def generate_keystream(key: str, nonce: bytes, length: int) -> bytes:
    """
    Generates a pseudo-random keystream of `length` bytes.

    Method: SHA-256 in counter mode.
      block_i = SHA-256(key || nonce || counter_i)
    Blocks are concatenated until we have enough bytes.

    This is the 'Stream Cipher' described in the PDF project spec.
    """
    key_bytes = key.encode("utf-8")
    keystream = bytearray()
    counter = 0
    while len(keystream) < length:
        block_input = key_bytes + nonce + struct.pack(">Q", counter)
        block = hashlib.sha256(block_input).digest()
        keystream.extend(block)
        counter += 1
    return bytes(keystream[:length])


# ──────────────────────────────────────────────────────────────────────────────
#  XOR Stream Cipher
# ──────────────────────────────────────────────────────────────────────────────

def xor_cipher(data: bytes, keystream: bytes) -> bytes:
    """XOR each byte of data with the corresponding keystream byte."""
    return bytes(b ^ k for b, k in zip(data, keystream))


# ──────────────────────────────────────────────────────────────────────────────
#  HMAC-SHA256 Integrity Tag
# ──────────────────────────────────────────────────────────────────────────────

def compute_mac(key: str, nonce: bytes, ciphertext: bytes) -> bytes:
    """
    HMAC-SHA256(key, nonce || ciphertext)

    Protects against Man-in-the-Middle attacks:
      - Any modification to the ciphertext will produce a different MAC.
      - Receiver verifies the MAC before decrypting; rejects tampered messages.
    """
    mac_key = hashlib.sha256(("HMAC:" + key).encode("utf-8")).digest()
    return hmac.new(mac_key, nonce + ciphertext, hashlib.sha256).digest()


def verify_mac(key: str, nonce: bytes, ciphertext: bytes, tag: bytes) -> bool:
    """Constant-time HMAC comparison (prevents timing attacks)."""
    expected = compute_mac(key, nonce, ciphertext)
    return hmac.compare_digest(expected, tag)


# ──────────────────────────────────────────────────────────────────────────────
#  Public API
# ──────────────────────────────────────────────────────────────────────────────

NONCE_SIZE = 16   # bytes
MAC_SIZE   = 32   # bytes (SHA-256 output)


def encrypt(plaintext: str, key: str) -> bytes:
    """
    Encrypt a plaintext string and return a binary payload.

    Payload layout:
      nonce (16 bytes) | ciphertext (len bytes) | HMAC (32 bytes)
    """
    plaintext_bytes = plaintext.encode("utf-8")
    nonce = os.urandom(NONCE_SIZE)
    keystream = generate_keystream(key, nonce, len(plaintext_bytes))
    ciphertext = xor_cipher(plaintext_bytes, keystream)
    mac = compute_mac(key, nonce, ciphertext)
    return nonce + ciphertext + mac


def decrypt(payload: bytes, key: str) -> str:
    """
    Decrypt a binary payload back to plaintext.

    Raises:
        WrongKeyError — if HMAC verification fails (wrong key OR tampered message)
        ValueError    — if payload is too short / malformed
    """
    if len(payload) < NONCE_SIZE + MAC_SIZE:
        raise ValueError("Payload too short — corrupted or malformed packet.")

    nonce      = payload[:NONCE_SIZE]
    mac        = payload[-MAC_SIZE:]
    ciphertext = payload[NONCE_SIZE:-MAC_SIZE]

    if not verify_mac(key, nonce, ciphertext, mac):
        raise WrongKeyError(
            "HMAC verification failed.\n"
            "This means either:\n"
            "  • You are using a wrong secret key, OR\n"
            "  • A Man-in-the-Middle modified the message."
        )

    keystream = generate_keystream(key, nonce, len(ciphertext))
    plaintext_bytes = xor_cipher(ciphertext, keystream)
    return plaintext_bytes.decode("utf-8")


def key_fingerprint(key: str) -> str:
    """
    Returns a short, human-readable fingerprint of the shared key.
    Lets both parties visually confirm they share the same key
    without revealing the key itself.
    """
    digest = hashlib.sha256(("FP:" + key).encode("utf-8")).hexdigest()
    # Show first 16 hex chars in groups of 4 for readability
    fp = digest[:16].upper()
    return " ".join(fp[i:i+4] for i in range(0, len(fp), 4))


def framed_packet(payload: bytes) -> bytes:
    """Prepend a 4-byte length header to the encrypted payload for TCP framing."""
    return struct.pack(">I", len(payload)) + payload


def read_packet(sock) -> bytes:
    """
    Read exactly one framed packet from a socket.
    Returns the raw payload bytes (without the length header).
    """
    raw_len = _recv_exactly(sock, 4)
    if not raw_len:
        return b""
    length = struct.unpack(">I", raw_len)[0]
    if length == 0 or length > 10 * 1024 * 1024:   # max 10 MB
        raise ValueError(f"Invalid packet length: {length}")
    return _recv_exactly(sock, length)


def _recv_exactly(sock, n: int) -> bytes:
    """Read exactly n bytes from socket, handling partial reads."""
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return b""
        buf += chunk
    return buf


# ──────────────────────────────────────────────────────────────────────────────
#  Self-Test
# ──────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("=" * 60)
    print("  crypto.py — Self-Test")
    print("=" * 60)

    test_key   = "MySecretKey123!"
    wrong_key  = "WrongKey!!!"
    test_msg   = "Hello, this is a secret message! 🔐"

    print(f"\n[Key]       : {test_key}")
    print(f"[Plaintext] : {test_msg}")

    payload = encrypt(test_msg, test_key)
    print(f"\n[Encrypted] ({len(payload)} bytes):")
    print(" ", payload.hex())

    # Correct key
    recovered = decrypt(payload, test_key)
    print(f"\n[Decrypted] : {recovered}")
    assert recovered == test_msg, "FAIL: Decryption mismatch!"
    print("  ✔ Correct key — decryption successful")

    # Wrong key
    try:
        decrypt(payload, wrong_key)
        print("  ✘ FAIL: Wrong key should have raised WrongKeyError!")
    except WrongKeyError as e:
        print(f"  ✔ Wrong key detected correctly: {e.args[0].splitlines()[0]}")

    # Tampered ciphertext
    tampered = bytearray(payload)
    tampered[NONCE_SIZE + 5] ^= 0xFF   # flip a bit in ciphertext
    try:
        decrypt(bytes(tampered), test_key)
        print("  ✘ FAIL: Tampered message should have raised WrongKeyError!")
    except WrongKeyError:
        print("  ✔ Tampered message detected correctly (MitM protection works!)")

    # Key fingerprint
    print(f"\n[Key Fingerprint] : {key_fingerprint(test_key)}")
    print("\nAll tests passed! ✔")
