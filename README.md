# Secure End-to-End Encrypted Chat

This repository contains a university project that demonstrates a secure chat messaging platform built with **Python**, **Flask**, **AES-256**, **HMAC-SHA256**, **bcrypt**, and **Diffie-Hellman (DH)** key exchange. It also ships with a **Brute Force Lab** for password hash and reduced-key AES attack simulations.

## Features

- User registration & login with bcrypt hashing and secure Flask sessions
- Real-time style chat using AJAX polling every few seconds
- Automatic Diffie-Hellman key exchange per chat pairing with HKDF key derivation
- AES-256 CBC encryption and HMAC integrity validation for every stored message
- SQLite database via SQLAlchemy storing only ciphertext + metadata (no plaintext)
- Login attempt logging plus admin dashboard for audit trails
- Rate-limited login: 5 failed attempts within 5 minutes trigger a 60-second cooldown
- Brute-force laboratory:
  - Dictionary attack simulation on bcrypt hashes
  - Reduced key-space AES brute-force demonstration (4–24 bit)
- Modular crypto layers (`crypto/`), database models (`database/`), and templates/static assets for maintainability

## Project Structure

- `app.py`: Flask application factory, routes, and brute-force simulations
- `config.py`: Centralized configuration + environment loading
- `crypto/`: AES/HMAC, bcrypt helpers, Diffie-Hellman key exchange, HKDF
- `database/`: SQLAlchemy initialization and ORM models
- `templates/` & `static/`: Bootstrap-based UI for auth, chat, logs, and labs
- `tests/`: Unit tests for cryptographic primitives (see below)
- `scripts/chat_database_report.py`: CLI utility that prints how encrypted chats (ciphertext + IV + HMAC) are stored in SQLite for demo purposes

## Getting Started

1. **Install dependencies**
   ```bash
   python -m venv .venv
   .venv\Scripts\activate  # Windows
   pip install -r requirements.txt
   ```
2. **Environment (optional)** – copy `.env.example` to `.env` and override secrets or database URL.
3. **Run the server**
   ```bash
   flask --app app:create_app --debug run
   ```
4. Register two users, start a chat, and open the Brute Force Lab to explore the simulations.

## Testing

```
pytest
```

Tests cover AES encryption/decryption, HMAC validation, bcrypt hashing, and DH shared key equality.

## Demonstrating Encrypted Storage

Use the helper script after sending a few chats:

```
python scripts/chat_database_report.py
```

It lists each message (ordered chronologically) showing the Base64 ciphertext, IV, and 32-byte HMAC tag so you can demonstrate to evaluators that only encrypted blobs—not plaintext—live inside the database.

## Screenshots & Documentation

- See `docs/` for architecture notes and include screenshots (login, chat, lab) before submission.
- Use the README plus the initial SRS prompt as project documentation for viva preparation (AES, HMAC, bcrypt, DH, brute force).

## Security Notes

- Private keys are stored plainly for simplicity—wrap them with server-side encryption (e.g., AES-GCM with a hardware-protected key) for production.
- Enable HTTPS, CSP headers, stricter cookie policies, and WebSockets/SignalR for real-time performance in future iterations.

