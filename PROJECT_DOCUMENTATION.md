# 🔐 Secure End-to-End Encrypted Chat - Complete Project Documentation

## 📋 Table of Contents
1. [Project Overview](#project-overview)
2. [Technology Stack](#technology-stack)
3. [Project Structure](#project-structure)
4. [File-by-File Analysis](#file-by-file-analysis)
5. [Security Features](#security-features)
6. [Database Schema](#database-schema)
7. [How It Works](#how-it-works)
8. [Running the Project](#running-the-project)
9. [Testing](#testing)

---

## 🎯 Project Overview

This is a **university project** demonstrating a secure chat messaging platform with end-to-end encryption. The application showcases multiple cryptographic concepts including:

- **AES-256 CBC Encryption** for message confidentiality
- **HMAC-SHA256** for message integrity verification
- **Diffie-Hellman Key Exchange** for secure key establishment
- **bcrypt** for password hashing
- **HKDF** for key derivation
- **Brute Force Lab** for educational attack simulations

**Key Features:**
- User registration and authentication with secure password hashing
- Real-time chat using AJAX polling
- Automatic key exchange between chat partners
- All messages stored encrypted in database (no plaintext)
- Login attempt tracking with rate limiting
- Admin dashboard for audit trails
- Educational brute-force attack simulations

---

## 🛠️ Technology Stack

### Backend
- **Flask 3.0.3** - Web framework
- **SQLAlchemy** - ORM for database operations
- **SQLite** - Database (can be changed to MySQL/PostgreSQL)
- **bcrypt 4.2.0** - Password hashing
- **pycryptodome 3.20.0** - Cryptographic operations (AES, HMAC)

### Frontend
- **Bootstrap** - UI framework
- **Vanilla JavaScript** - AJAX polling for real-time updates
- **HTML/CSS** - Templates and styling

### Security Libraries
- **Flask-WTF** - CSRF protection
- **python-dotenv** - Environment variable management
- **secrets** - Cryptographically strong random number generation

---

## 📁 Project Structure

```
Information security/
│
├── 📄 app.py                          # Main Flask application (402 lines)
├── 📄 config.py                       # Configuration settings (37 lines)
├── 📄 requirements.txt                # Python dependencies
├── 📄 .env.example                    # Environment variables template
├── 📄 secure_chat.db                  # SQLite database
├── 📄 README.md                       # Project README
│
├── 📁 crypto/                         # Cryptography modules
│   ├── __init__.py                    # Package initialization
│   ├── encryption.py                  # AES-256 CBC encryption/decryption
│   ├── hashing.py                     # bcrypt password hashing
│   ├── key_exchange.py                # Diffie-Hellman key exchange
│   └── utils.py                       # HMAC, HKDF, encoding utilities
│
├── 📁 database/                       # Database layer
│   ├── __init__.py                    # SQLAlchemy initialization
│   └── models.py                      # ORM models (User, Message, etc.)
│
├── 📁 templates/                      # HTML templates
│   ├── base.html                      # Base template with Bootstrap
│   ├── login.html                     # Login page
│   ├── register.html                  # Registration page
│   ├── chat_list.html                 # List of available users
│   ├── chat.html                      # Chat interface
│   ├── brute_force.html               # Brute force lab
│   └── admin_logs.html                # Admin audit logs
│
├── 📁 static/                         # Static assets
│   ├── css/
│   │   └── main.css                   # Custom styles
│   └── js/
│       └── chat.js                    # AJAX polling & message handling
│
├── 📁 scripts/                        # Utility scripts
│   └── chat_database_report.py        # Shows encrypted storage format
│
├── 📁 tests/                          # Unit tests
│   └── test_crypto.py                 # Cryptographic function tests
│
├── 📁 docs/                           # Documentation
│   └── architecture.md                # Architecture overview
│
└── 📁 information_security/           # Virtual environment (venv)
```

---

## 📝 File-by-File Analysis

### 🔹 **app.py** (Main Application - 402 lines)

**Purpose:** Core Flask application with all routes and business logic.

**Key Components:**

1. **Application Factory Pattern**
   ```python
   def create_app(config_class: type[Config] = Config) -> Flask:
   ```
   - Creates Flask app instance
   - Initializes database
   - Registers all routes

2. **Authentication & Authorization**
   - `current_user()` - Gets logged-in user from session
   - `login_required` - Decorator to protect routes
   - `store_login_attempt()` - Logs all login attempts
   - `lockout_remaining_seconds()` - Rate limiting (5 attempts in 5 min = 60s lockout)

3. **Key Management**
   - `get_shared_key_for_users()` - Derives shared encryption key using Diffie-Hellman
   - `_session_key()` - Creates unique session key identifier for user pairs

4. **Routes:**
   - `/` - Home (redirects to login or chat)
   - `/register` - User registration with bcrypt hashing
   - `/login` - Authentication with rate limiting
   - `/logout` - Session cleanup
   - `/chat` - Chat list (all users)
   - `/chat/<username>` - Chat interface with specific user
   - `/send_message` - API endpoint to send encrypted message
   - `/get_messages/<username>` - API endpoint to fetch & decrypt messages
   - `/brute_force` - Educational brute force lab
   - `/bruteforce_password` - Dictionary attack simulation on bcrypt
   - `/bruteforce_key` - Reduced-key AES brute force (4-24 bit)
   - `/admin/logs` - Audit trail dashboard

5. **Security Features:**
   - Password validation (min 8 characters)
   - Username uniqueness check
   - HMAC verification before decryption
   - Session-based authentication
   - IP address logging

---

### 🔹 **config.py** (Configuration - 37 lines)

**Purpose:** Centralized configuration management.

**Key Settings:**
- `SECRET_KEY` - Flask session encryption (from .env or default)
- `SQLALCHEMY_DATABASE_URI` - Database connection string
- `MASTER_KEY` - 256-bit key for future encryption needs
- `CHAT_POLL_INTERVAL` - AJAX polling frequency (default: 2 seconds)
- `LOGIN_LOCKOUT_THRESHOLD` - Failed attempts before lockout (default: 5)
- `LOGIN_LOCKOUT_DURATION_SECONDS` - Lockout duration (default: 60s)
- `LOGIN_ATTEMPT_WINDOW_MINUTES` - Time window for counting failures (default: 5 min)

**Security Configurations:**
- `SESSION_COOKIE_HTTPONLY = True` - Prevents XSS attacks
- `SESSION_COOKIE_SAMESITE = "Lax"` - CSRF protection
- `REMEMBER_COOKIE_HTTPONLY = True` - Cookie security

**Test Configuration:**
- `TestConfig` class for in-memory SQLite testing

---

### 🔹 **crypto/encryption.py** (AES Encryption - 70 lines)

**Purpose:** AES-256 CBC encryption with HMAC integrity.

**Key Functions:**

1. **`_pad(data: bytes) -> bytes`**
   - Implements PKCS#7 padding for AES block alignment
   - Ensures data is multiple of 16 bytes

2. **`_unpad(data: bytes) -> bytes`**
   - Removes PKCS#7 padding after decryption
   - Validates padding integrity

3. **`encrypt(shared_key: bytes, plaintext: str) -> EncryptedPayload`**
   - Generates random 16-byte IV
   - Encrypts plaintext using AES-256 CBC
   - Computes HMAC-SHA256 over IV + ciphertext
   - Returns: `EncryptedPayload(ciphertext, iv, hmac_tag)`

4. **`decrypt(shared_key: bytes, payload: EncryptedPayload) -> str`**
   - Verifies HMAC first (authenticate-then-decrypt)
   - Decrypts ciphertext using AES-256 CBC
   - Removes padding and returns plaintext
   - Raises `ValueError` if HMAC verification fails

**Data Structure:**
```python
@dataclass
class EncryptedPayload:
    ciphertext: bytes
    iv: bytes
    hmac_tag: bytes
```

---

### 🔹 **crypto/hashing.py** (Password Hashing - 17 lines)

**Purpose:** Secure password hashing using bcrypt.

**Key Functions:**

1. **`hash_password(password: str) -> bytes`**
   - Uses bcrypt with 12 rounds (2^12 = 4096 iterations)
   - Automatically generates random salt
   - Returns hashed password as bytes

2. **`verify_password(password: str, hashed: bytes) -> bool`**
   - Constant-time comparison to prevent timing attacks
   - Returns True if password matches hash
   - Handles exceptions gracefully

**Security:**
- bcrypt is designed to be slow (prevents brute force)
- Automatic salt generation (prevents rainbow table attacks)
- Configurable work factor (rounds=12)

---

### 🔹 **crypto/key_exchange.py** (Diffie-Hellman - 41 lines)

**Purpose:** Secure key exchange using Diffie-Hellman.

**Key Components:**

1. **Constants:**
   - `P` - 2048-bit MODP prime from RFC 3526
   - `G` - Generator (2)

2. **`generate_private_key() -> int`**
   - Generates cryptographically secure random private key
   - Range: [2, P-1]

3. **`generate_key_pair() -> KeyPair`**
   - Creates private key
   - Computes public key: `G^private mod P`
   - Returns both as `KeyPair` dataclass

4. **`compute_shared_key(private_key: int, peer_public_key: int) -> bytes`**
   - Computes shared secret: `peer_public^private mod P`
   - Derives 32-byte AES key using HKDF-SHA256
   - Both parties compute same shared key

**Security:**
- 2048-bit key size (strong security)
- HKDF key derivation (prevents weak keys)
- Ephemeral keys per chat session

---

### 🔹 **crypto/utils.py** (Utilities - 40 lines)

**Purpose:** Cryptographic utility functions.

**Key Functions:**

1. **`sha256_digest(data: bytes) -> bytes`**
   - Computes SHA-256 hash

2. **`hkdf_sha256(shared_secret: int, info: bytes) -> bytes`**
   - HKDF-style key derivation
   - Converts DH shared secret to 32-byte AES key
   - Uses HMAC-SHA256 for extraction and expansion

3. **`encode_bytes(data: bytes) -> str`**
   - Base64 encodes bytes for database storage

4. **`decode_bytes(data: str) -> bytes`**
   - Base64 decodes string back to bytes

5. **`generate_hmac(key: bytes, data: bytes) -> bytes`**
   - Computes HMAC-SHA256 tag (32 bytes)

6. **`verify_hmac(key: bytes, data: bytes, expected: bytes) -> bool`**
   - Constant-time HMAC verification
   - Prevents timing attacks

---

### 🔹 **database/models.py** (ORM Models - 72 lines)

**Purpose:** SQLAlchemy database models.

**Models:**

1. **`User` Model**
   ```python
   - id: Integer (Primary Key)
   - username: String(80) (Unique, Not Null)
   - password_hash: LargeBinary(128) (bcrypt hash)
   - public_key: Text (DH public key)
   - private_key: Text (DH private key - should be encrypted in production)
   - created_at: DateTime
   - Relationships: messages_sent, messages_received
   ```

2. **`Message` Model**
   ```python
   - id: Integer (Primary Key)
   - sender_id: Integer (Foreign Key -> users.id)
   - receiver_id: Integer (Foreign Key -> users.id)
   - encrypted_message: Text (Base64 ciphertext)
   - iv: Text (Base64 initialization vector)
   - hmac: Text (Base64 HMAC-SHA256 tag)
   - timestamp: DateTime (Indexed)
   - Relationships: sender_user, receiver_user
   ```

3. **`LoginAttempt` Model**
   ```python
   - id: Integer (Primary Key)
   - username: String(80)
   - success: Boolean
   - ip_address: String(64)
   - created_at: DateTime (Indexed)
   ```

4. **`BruteForceLog` Model**
   ```python
   - id: Integer (Primary Key)
   - attack_type: String(32) ('password' or 'aes')
   - attempts: Integer
   - duration_ms: Float
   - result: String(32) ('success' or 'failure')
   - created_at: DateTime (Indexed)
   ```

**Security Note:** Private keys stored in plaintext for simplicity. In production, encrypt with master key.

---

### 🔹 **static/js/chat.js** (Frontend Logic - 117 lines)

**Purpose:** Real-time chat interface with AJAX polling.

**Key Functions:**

1. **`buildMessageBubble(msg)`**
   - Creates chat bubble HTML
   - Different styling for sender vs receiver
   - Shows avatar, message content, timestamp

2. **`buildDateSeparator(date)`**
   - Creates date separator between messages
   - Groups messages by day

3. **`fetchMessages()`**
   - AJAX GET request to `/get_messages/<username>`
   - Updates UI only if new messages exist
   - Auto-scrolls to bottom
   - Polls every 2 seconds (configurable)

4. **`sendMessage(evt)`**
   - AJAX POST request to `/send_message`
   - Sends JSON payload: `{receiver, message}`
   - Clears input and refreshes messages on success

**Polling Mechanism:**
```javascript
setInterval(fetchMessages, window.chatConfig.pollInterval * 1000);
```

---

### 🔹 **scripts/chat_database_report.py** (Utility - 66 lines)

**Purpose:** Demonstrates encrypted storage format.

**Functionality:**
- Connects to database
- Fetches all messages
- Displays ciphertext, IV, and HMAC in Base64
- Shows that NO plaintext is stored
- Useful for project demonstrations/viva

**Usage:**
```bash
python scripts/chat_database_report.py
```

**Output Example:**
```
Message ID     : 1
Timestamp      : 2025-12-19T12:00:00
Participants   : alice -> bob
Ciphertext (b64): U2FsdGVkX1+vupppZksvRf5pq5g5XjFRIipRkwB0K1Y96Qsv2Lm+31cmzaAILwyt...
IV (b64)       : 1234567890abcdef1234567890ab...
HMAC (b64)     : a3f5b8c9d2e1f4a7b6c5d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9...
HMAC length    : 32 bytes (SHA-256)
```

---

### 🔹 **tests/test_crypto.py** (Unit Tests - 34 lines)

**Purpose:** Automated testing of cryptographic functions.

**Test Cases:**

1. **`test_aes_encrypt_decrypt_roundtrip()`**
   - Generates two DH key pairs
   - Computes shared keys (should be equal)
   - Encrypts plaintext with one key
   - Decrypts with other key
   - Verifies plaintext matches

2. **`test_hmac_generation_and_validation()`**
   - Generates HMAC tag
   - Verifies correct tag passes
   - Verifies tampered data fails

3. **`test_bcrypt_hashing_roundtrip()`**
   - Hashes password
   - Verifies correct password
   - Verifies wrong password fails

**Run Tests:**
```bash
pytest
```

---

## 🔒 Security Features

### 1. **End-to-End Encryption**
- Messages encrypted with AES-256 CBC
- Unique IV per message (prevents pattern analysis)
- HMAC-SHA256 for integrity (detect tampering)
- Only ciphertext stored in database

### 2. **Secure Key Exchange**
- Diffie-Hellman 2048-bit (RFC 3526)
- HKDF key derivation
- Session-cached shared keys

### 3. **Password Security**
- bcrypt hashing (12 rounds)
- Automatic salt generation
- Minimum 8 characters
- Constant-time verification

### 4. **Authentication & Authorization**
- Session-based authentication
- HttpOnly cookies (XSS protection)
- SameSite=Lax (CSRF protection)
- Login rate limiting (5 attempts/5min)

### 5. **Audit Trail**
- All login attempts logged (success/failure)
- IP address tracking
- Brute force attack logging
- Admin dashboard for monitoring

### 6. **Input Validation**
- Username uniqueness check
- Password confirmation
- Empty message prevention
- SQL injection protection (SQLAlchemy ORM)

---

## 🗄️ Database Schema

```sql
-- Users Table
CREATE TABLE users (
    id INTEGER PRIMARY KEY,
    username VARCHAR(80) UNIQUE NOT NULL,
    password_hash BLOB(128) NOT NULL,
    public_key TEXT NOT NULL,
    private_key TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Messages Table (All encrypted)
CREATE TABLE messages (
    id INTEGER PRIMARY KEY,
    sender_id INTEGER NOT NULL,
    receiver_id INTEGER NOT NULL,
    encrypted_message TEXT NOT NULL,  -- Base64 ciphertext
    iv TEXT NOT NULL,                 -- Base64 IV
    hmac TEXT NOT NULL,               -- Base64 HMAC tag
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (sender_id) REFERENCES users(id),
    FOREIGN KEY (receiver_id) REFERENCES users(id)
);
CREATE INDEX idx_messages_timestamp ON messages(timestamp);

-- Login Attempts Table
CREATE TABLE login_attempts (
    id INTEGER PRIMARY KEY,
    username VARCHAR(80),
    success BOOLEAN DEFAULT 0,
    ip_address VARCHAR(64),
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX idx_login_attempts_created_at ON login_attempts(created_at);

-- Brute Force Logs Table
CREATE TABLE brute_force_logs (
    id INTEGER PRIMARY KEY,
    attack_type VARCHAR(32) NOT NULL,  -- 'password' or 'aes'
    attempts INTEGER NOT NULL,
    duration_ms FLOAT NOT NULL,
    result VARCHAR(32) NOT NULL,       -- 'success' or 'failure'
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX idx_brute_force_logs_created_at ON brute_force_logs(created_at);
```

---

## ⚙️ How It Works

### **Registration Flow:**
1. User enters username and password
2. Password hashed with bcrypt (12 rounds)
3. DH key pair generated (public + private)
4. User record saved to database
5. Redirect to login

### **Login Flow:**
1. User enters credentials
2. Check rate limiting (5 attempts/5min)
3. Fetch user by username
4. Verify password with bcrypt
5. Create Flask session with user_id
6. Log successful attempt
7. Redirect to chat list

### **Chat Initialization:**
1. User selects chat partner
2. Fetch both users' DH keys
3. Compute shared secret: `peer_public^my_private mod P`
4. Derive AES-256 key using HKDF
5. Cache shared key in session
6. Load chat interface

### **Sending Message:**
1. User types message and clicks send
2. JavaScript sends AJAX POST to `/send_message`
3. Backend retrieves shared key from session
4. Encrypt plaintext:
   - Generate random 16-byte IV
   - AES-256 CBC encryption
   - Compute HMAC-SHA256 over IV + ciphertext
5. Store `(ciphertext, IV, HMAC)` in database as Base64
6. Return success response
7. Frontend refreshes messages

### **Receiving Messages:**
1. JavaScript polls `/get_messages/<username>` every 2 seconds
2. Backend fetches all messages between users
3. For each message:
   - Decode Base64 to bytes
   - Verify HMAC (integrity check)
   - Decrypt ciphertext with AES-256 CBC
   - Remove padding
4. Return JSON array of plaintext messages
5. Frontend renders chat bubbles

### **Brute Force Lab:**

**Password Attack:**
1. User provides bcrypt hash and dictionary
2. Backend tries each word with bcrypt.checkpw()
3. Logs attempts, duration, result
4. Demonstrates bcrypt's slowness (defense)

**AES Key Attack:**
1. User selects key size (4-24 bits)
2. Backend encrypts test message with known key
3. Tries all possible keys (2^n combinations)
4. Logs attempts, duration, result
5. Demonstrates importance of key length

---

## 🚀 Running the Project

### **1. Setup Virtual Environment:**
```bash
# Create venv
python -m venv information_security

# Activate (Windows)
information_security\Scripts\activate

# Activate (Linux/Mac)
source information_security/bin/activate
```

### **2. Install Dependencies:**
```bash
pip install -r requirements.txt
```

### **3. Configure Environment (Optional):**
```bash
# Copy example
cp .env.example .env

# Edit .env with your settings
SECRET_KEY=your-secret-key-here
CHAT_POLL_INTERVAL=2
```

### **4. Run Application:**
```bash
# Development mode
flask --app app:create_app --debug run

# Production mode
python app.py
```

### **5. Access Application:**
- Open browser: `http://127.0.0.1:5000`
- Register two users (e.g., alice, bob)
- Login and start chatting!

---

## 🧪 Testing

### **Run Unit Tests:**
```bash
pytest
```

### **Run with Coverage:**
```bash
pytest --cov=crypto --cov=database
```

### **Test Scenarios:**
1. **Registration:** Create multiple users
2. **Login:** Test correct/incorrect passwords
3. **Rate Limiting:** Try 6+ failed logins
4. **Chat:** Send messages between users
5. **Encryption:** Verify database contains only ciphertext
6. **Brute Force:** Run password/AES attacks
7. **Admin Logs:** Check audit trail

---

## 📚 Key Concepts Demonstrated

### **Cryptography:**
- ✅ Symmetric encryption (AES-256)
- ✅ Asymmetric key exchange (Diffie-Hellman)
- ✅ Message authentication (HMAC-SHA256)
- ✅ Password hashing (bcrypt)
- ✅ Key derivation (HKDF)
- ✅ Padding schemes (PKCS#7)

### **Security:**
- ✅ Authentication & authorization
- ✅ Session management
- ✅ Rate limiting
- ✅ Audit logging
- ✅ Input validation
- ✅ CSRF protection
- ✅ XSS prevention

### **Software Engineering:**
- ✅ MVC architecture
- ✅ Modular design
- ✅ ORM (SQLAlchemy)
- ✅ RESTful APIs
- ✅ Unit testing
- ✅ Configuration management
- ✅ Documentation

---

## 🎓 Educational Value

This project is perfect for:
- **Information Security courses** - Demonstrates practical cryptography
- **Web Development courses** - Shows full-stack Flask application
- **Database courses** - Illustrates ORM and schema design
- **Software Engineering** - Exhibits modular architecture

**Viva Preparation Topics:**
1. Explain AES-256 CBC mode
2. How does Diffie-Hellman work?
3. Why use HMAC before decryption?
4. What is bcrypt's work factor?
5. How does rate limiting prevent attacks?
6. Explain the database schema
7. What are the security weaknesses? (private key storage, polling vs WebSockets)

---

## ⚠️ Security Notes (Production Considerations)

**Current Limitations:**
1. ❌ Private keys stored in plaintext (should be encrypted with master key)
2. ❌ HTTP only (should use HTTPS)
3. ❌ Polling instead of WebSockets (inefficient)
4. ❌ No CSRF tokens on forms (relies on SameSite cookies)
5. ❌ SQLite (should use PostgreSQL/MySQL for production)

**Recommended Improvements:**
1. ✅ Encrypt private keys at rest (AES-GCM with HSM-protected master key)
2. ✅ Enable HTTPS with valid SSL certificate
3. ✅ Implement WebSockets for real-time messaging
4. ✅ Add Flask-WTF CSRF tokens to all forms
5. ✅ Use production database (PostgreSQL)
6. ✅ Add Content Security Policy (CSP) headers
7. ✅ Implement message deletion/editing
8. ✅ Add file attachment support
9. ✅ Implement read receipts
10. ✅ Add role-based access control (RBAC)

---

## 📞 Support & Resources

**Documentation:**
- Flask: https://flask.palletsprojects.com/
- SQLAlchemy: https://www.sqlalchemy.org/
- PyCryptodome: https://pycryptodome.readthedocs.io/
- bcrypt: https://github.com/pyca/bcrypt/

**Cryptography References:**
- RFC 3526 (DH Groups): https://www.rfc-editor.org/rfc/rfc3526
- NIST AES: https://csrc.nist.gov/publications/detail/fips/197/final
- HMAC RFC 2104: https://www.rfc-editor.org/rfc/rfc2104

---

## 📄 License

This is a university educational project. Use for learning purposes.

---

**Created for Information Security Course**  
**Last Updated:** December 19, 2025  
**Version:** 1.0
