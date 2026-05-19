# 🔒 SecureChat

![Shield](https://img.shields.io/badge/security-end--to--end%20encrypted-brightgreen?style=for-the-badge&logo=shield&logoColor=white)
![Python](https://img.shields.io/badge/Python-3.x-blue?style=for-the-badge&logo=python&logoColor=white)
![WebSocket](https://img.shields.io/badge/WebSocket-relay-orange?style=for-the-badge&logo=websocket&logoColor=white)
![License](https://img.shields.io/badge/license-Academic-lightgrey?style=for-the-badge)

---
> **End-to-end encrypted chat application built from scratch — no black-box libraries. Every cryptographic primitive implemented manually using SHA-256 counter mode keystream, XOR stream cipher, and HMAC-SHA256 over a WebSocket relay.**

---

## 📖 About the Project

**SecureChat** is a fully functional, end-to-end encrypted messaging application built from scratch as a university data security course project. The application enables real-time secure communication over local or public networks using a layered cryptographic stack that combines a stream cipher with message authentication.

Rather than relying on third-party encryption libraries as a black box, the **full cryptographic pipeline was implemented manually** — from keystream generation and XOR encryption to HMAC authentication and nonce framing — in both Python (server and desktop backend) and JavaScript (browser client). This gives every component direct, transparent insight into how each security primitive works and how they compose into a complete secure system.

---

## ✨ Features

- 🔐 **Real-time encrypted chat** via WebSocket relay server
- 🌐 **Browser-based client** — no installation needed on the client side
- 🖥️ **Python desktop client** built with Tkinter for host/guest TCP mode
- 🔑 **XOR stream cipher** with SHA-256 counter mode keystream generation
- 🛡️ **HMAC-SHA256** message authentication and tamper detection
- 🎲 **Random 16-byte nonce** per message for replay protection and semantic security
- 🕵️ **Built-in attacker simulation view** for live Man-in-the-Middle classroom demonstration
- 📎 **Encrypted file attachments** — securely send any file type within a chat session
- 🎙️ **Encrypted voice messages** — record and send end-to-end encrypted audio clips
- 🌍 **Public URL via Ngrok tunnel** for cross-network connectivity without port forwarding
- 🔍 **Key fingerprint** for visual shared-secret verification between peers

---

## 🔐 Cryptographic Stack

| Component | Algorithm | Purpose |
|---|---|---|
| Keystream Generation | SHA-256 Counter Mode | Produces pseudo-random bytes for encryption |
| Encryption | XOR Stream Cipher | Byte-by-byte encryption and decryption |
| Authentication | HMAC-SHA256 | Tamper detection and message integrity |
| Nonce | `os.urandom(16)` — 16 random bytes | Replay protection and semantic security |
| Room ID | SHA-256 hash of password | Zero-knowledge room matching on the server |

### Wire Format

Every transmitted packet follows this exact binary layout:

```
[ 16 bytes : Nonce         ]  — random, unique per message
[ N  bytes : Ciphertext    ]  — plaintext XOR keystream
[ 32 bytes : HMAC-SHA256   ]  — authentication tag over (nonce || ciphertext)
```

*In TCP mode, a 4-byte big-endian length header is prepended for stream framing.*

---

## 🗂️ Project Structure

```
SecureChat/
│
├── server.py       # asyncio WebSocket relay server + HTTP server + Ngrok tunnel
├── crypto.py       # Core crypto engine: keystream, XOR cipher, HMAC, TCP framing
├── client.py       # Python TCP socket client connecting to server.py host
├── chat_gui.py     # Tkinter desktop GUI for host/guest TCP mode
├── index.html      # Browser-based chat UI — mirrors crypto.py logic in JavaScript
├── attacker.html   # Attacker simulation view with live cracking console
└── start.bat       # Windows one-click launcher — installs deps and starts server       
```

---

## 🚀 How to Run

### Requirements

```bash
Python 3.x
pip install websockets
Ngrok installed and authenticated (https://ngrok.com)
```

### Option 1 — Windows (Recommended)

Simply double-click `start.bat`. It will automatically kill any conflicting processes on ports 8080 and 8765, install dependencies, and start the server.

### Option 2 — Manual

```bash
python server.py
```

### Connect

1. Open your browser and go to:
```
http://localhost:8080
```
2. Copy the **Ngrok public URL** printed in the terminal and share it with the other person.
3. Both users enter the **same password** to join the same encrypted room.
4. Start chatting — all messages, files, and voice clips are encrypted end-to-end.

### Attacker Simulation

To demonstrate MitM protection in a classroom setting, open the Ngrok URL on a **third device** and join the same room. The attacker view automatically activates with a live cracking console.

---

## ⚙️ How It Works

When a user enters a password, the browser computes `SHA-256("ROOM:" || password)` client-side and sends only the resulting hash to the server as the room ID — the actual password never leaves the device. The encryption key is derived from the first 4 characters of the password and also never transmitted. For every message, a fresh 16-byte cryptographically secure random nonce is generated via `os.urandom()`. The keystream is then produced by computing `SHA-256(key || nonce || counter)` repeatedly in counter mode, concatenating 32-byte blocks until enough bytes are available. The plaintext is XOR-ed byte-by-byte with the keystream to produce ciphertext. An HMAC-SHA256 tag is computed over `(nonce || ciphertext)` using a domain-separated MAC key and appended to the packet. The relay server receives and forwards only the opaque binary packet — it never has access to the key, the password, or any plaintext.

---

## 🛡️ Security Properties

| ✅ Implemented | ❌ Not Yet Implemented |
|---|---|
| Confidentiality — XOR stream cipher with SHA-256 keystream | Forward Secrecy — static shared key, no per-session key exchange |
| Integrity — HMAC-SHA256 over (nonce \|\| ciphertext) | Mutual Authentication — pre-shared key model only |
| Replay Protection — random 16-byte nonce per message | Nonce Replay Cache — replay attack remains a theoretical gap |
| MitM Detection — HMAC fails if any byte is altered | |
| Key Privacy — password hashed before leaving client | |
| Timing Attack Resistance — `hmac.compare_digest()` | |

---

## ⚠️ Known Limitations

- **Weak key** — the encryption key is only the first 4 characters of the password, providing a very limited keyspace vulnerable to brute force
- **No key derivation function** — raw characters are used directly instead of PBKDF2 or Argon2
- **No forward secrecy** — the same static key is reused across all sessions; past messages are exposed if the key is compromised
- **No nonce replay cache** — the server does not track used nonces, leaving a theoretical replay attack gap

---

## 🔭 Future Work

- 🔄 **Diffie-Hellman key exchange** — eliminate out-of-band key sharing and provide forward secrecy
- 🔒 **Upgrade to AES-256-GCM or ChaCha20-Poly1305** — industry-standard authenticated encryption
- 🧂 **PBKDF2 or Argon2 key derivation** — strengthen low-entropy passwords against brute force
- 📋 **Nonce replay cache** — detect and reject replayed packets from active attackers
- 🪪 **Certificate-based identity verification** — prevent impersonation before session begins
- 👥 **Multi-party rooms** — support more than two simultaneous users per room


---

*SecureChat — because the server should never know what you said.*
