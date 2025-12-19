# Secure Chat Architecture Overview

## Layers

1. **Presentation** – `templates/`, Bootstrap UI, AJAX polling via `static/js/chat.js`.
2. **Application** – `app.py` routes + Flask session handling.
3. **Security/Crypto** – `crypto/` modules (Diffie-Hellman, AES-256 CBC, HMAC-SHA256, bcrypt).
4. **Persistence** – SQLAlchemy models stored in SQLite (`database/models.py`).

## Data Flow

1. User registers → bcrypt hash stored, DH key pair generated.
2. Login → Flask session with `user_id`; login attempts recorded.
3. Chat start → `get_shared_key_for_users` derives AES key via DH + HKDF, cached in session.
4. Send message → plaintext encrypted (AES-256), HMAC appended, ciphertext stored.
5. Receive message → payload fetched → HMAC verified → decrypted → rendered.
6. Brute-force lab → attack simulations log metadata only (not plaintext) for admin visibility.

## Database Schema

- `users(id, username, password_hash, public_key, private_key, created_at)`
- `messages(id, sender_id, receiver_id, encrypted_message, iv, hmac, timestamp)`
- `login_attempts(id, username, success, ip_address, created_at)`
- `brute_force_logs(id, attack_type, attempts, duration_ms, result, created_at)`

## Security Controls

- Bcrypt hashing before persistence.
- Diffie-Hellman + HKDF for chat-specific symmetric keys.
- AES-256 CBC with random IV per message.
- HMAC-SHA256 integrity enforcement.
- Session hardening: HttpOnly cookies, same-site Lax, session clear on login/logout.
- CSRF handled via same-site cookies & POST forms; add WTForms CSRF tokens (Flask-WTF) if required.

## Future Enhancements

- Replace polling with WebSockets.
- Encrypt user private keys at rest using master key derived from HSM/KeyVault.
- Add role-based admin controls and audit exports.
- Implement message attachments and read receipts.
- Introduce unit/integration tests for Flask routes and Web UI flows.

