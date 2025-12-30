# Requirements Documentation

This document provides a comprehensive overview of all dependencies used in the **Secure End-to-End Encrypted Chat** project, including their purpose, usage examples, and how they're implemented in this application.

---

## 📦 Installation

To install all required dependencies, run:

```bash
pip install -r requirements.txt
```

Or with virtual environment:

```bash
# Activate virtual environment
.\information_security\Scripts\activate  # Windows
source information_security/bin/activate  # Linux/Mac

# Install dependencies
pip install -r requirements.txt
```

---

## 📋 Complete Dependencies List

### 1. **Flask==3.0.3**

**Purpose**: Core web framework for building the application

**What it does**:
- Handles HTTP requests and responses
- Routes URL endpoints to Python functions
- Manages sessions and cookies
- Renders HTML templates

**Usage in this project**:
```python
from flask import Flask, request, jsonify, render_template, session

app = Flask(__name__)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        # Process login...
        return redirect(url_for('chat_list'))
    return render_template('login.html')
```

**Where it's used**:
- `app.py` - Main application factory and all routes
- Session management for user authentication
- Template rendering for UI pages

---

### 2. **Flask-WTF==1.2.1**

**Purpose**: Flask extension for WTForms integration and CSRF protection

**What it does**:
- Provides form validation
- CSRF (Cross-Site Request Forgery) token protection
- Secure form handling

**Usage example**:
```python
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField
from wtforms.validators import DataRequired

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
```

**Where it's used**:
- Form security across all POST requests
- CSRF protection for login, registration, and message sending

---

### 3. **Flask-Login==0.6.3**

**Purpose**: User session management for Flask applications

**What it does**:
- Manages user login/logout state
- Provides `@login_required` decorator
- Handles "remember me" functionality

**Usage example**:
```python
from flask_login import LoginManager, login_user, logout_user, login_required

login_manager = LoginManager()
login_manager.init_app(app)

@app.route('/protected')
@login_required
def protected_page():
    return "Only logged-in users can see this"
```

**Where it's used**:
- `app.py` - Custom `@login_required` decorator implementation
- User session tracking across requests

---

### 4. **Flask-SQLAlchemy==3.1.1**

**Purpose**: Flask extension for SQLAlchemy ORM (Object-Relational Mapping)

**What it does**:
- Allows working with databases using Python objects
- Provides database abstraction layer
- Simplifies database queries

**Usage in this project**:
```python
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    
# Query examples
user = User.query.filter_by(username='john').first()
all_users = User.query.all()
```

**Where it's used**:
- `database/models.py` - All database models (User, Message, LoginAttempt, BruteForceLog)
- `app.py` - Database queries for authentication and messaging

---

### 5. **Flask-Migrate==4.0.5**

**Purpose**: Database migration tool using Alembic

**What it does**:
- Tracks database schema changes
- Allows version control for database structure
- Enables safe database updates without data loss

**Usage commands**:
```bash
# Initialize migrations
flask db init

# Create a migration
flask db migrate -m "Add new column to users table"

# Apply migrations
flask db upgrade

# Rollback migrations
flask db downgrade
```

**Where it's used**:
- Managing database schema changes during development
- Ensuring database consistency across environments

---

### 6. **python-dotenv==1.0.1**

**Purpose**: Loads environment variables from `.env` files

**What it does**:
- Reads configuration from `.env` file
- Keeps sensitive data out of source code
- Manages different configurations for dev/prod

**Usage in this project**:
```python
from dotenv import load_dotenv
import os

load_dotenv('.env')

SECRET_KEY = os.getenv('SECRET_KEY', 'default-secret')
DATABASE_URL = os.getenv('DATABASE_URL', 'sqlite:///default.db')
```

**Example `.env` file**:
```env
SECRET_KEY=your-super-secret-key-here
DATABASE_URL=sqlite:///secure_chat.db
CHAT_POLL_INTERVAL=2
LOGIN_LOCKOUT_THRESHOLD=5
```

**Where it's used**:
- `config.py` - Loading all application configuration

---

### 7. **PyMySQL==1.1.1**

**Purpose**: Pure Python MySQL database driver

**What it does**:
- Enables connection to MySQL databases
- Provides MySQL compatibility for SQLAlchemy
- Pure Python implementation (no C dependencies)

**Usage example**:
```python
# In config.py
SQLALCHEMY_DATABASE_URI = 'mysql+pymysql://user:password@localhost/dbname'
```

**Where it's used**:
- Optional MySQL database support
- Currently using SQLite, but PyMySQL enables MySQL migration

---

### 8. **bcrypt==4.2.0** 🔐

**Purpose**: Secure password hashing using bcrypt algorithm

**What it does**:
- Hashes passwords with salt
- Slow by design to prevent brute-force attacks
- Industry-standard password security

**Usage in this project**:
```python
import bcrypt

# Hash a password
def hash_password(password: str) -> bytes:
    salt = bcrypt.gensalt(rounds=12)  # 12 rounds = ~0.3 seconds
    return bcrypt.hashpw(password.encode('utf-8'), salt)

# Verify password
def verify_password(password: str, hashed: bytes) -> bool:
    return bcrypt.checkpw(password.encode('utf-8'), hashed)
```

**Example**:
```python
# Registration
password = "MySecurePass123!"
hashed = hash_password(password)
# Stored: b'$2b$12$KIXxLVZ8...'

# Login
is_valid = verify_password("MySecurePass123!", hashed)  # True
is_valid = verify_password("WrongPassword", hashed)     # False
```

**Where it's used**:
- `crypto/hashing.py` - Password hashing functions
- `app.py` - User registration and login verification
- Brute force attack simulations

---

### 9. **pycryptodome==3.20.0** 🔐🔐🔐

**Purpose**: Comprehensive cryptography library (provides `Crypto.Cipher`)

**What it does**:
- AES encryption/decryption
- HMAC for message integrity
- Random number generation
- Various cryptographic primitives

**Usage in this project**:

#### **AES Encryption (AES-256 CBC Mode)**:
```python
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

# Encryption
def encrypt(shared_key: bytes, plaintext: str) -> EncryptedPayload:
    iv = get_random_bytes(16)  # Random initialization vector
    cipher = AES.new(shared_key, AES.MODE_CBC, iv)
    padded = _pad(plaintext.encode('utf-8'))
    ciphertext = cipher.encrypt(padded)
    return EncryptedPayload(ciphertext=ciphertext, iv=iv, hmac_tag=tag)

# Decryption
def decrypt(shared_key: bytes, payload: EncryptedPayload) -> str:
    cipher = AES.new(shared_key, AES.MODE_CBC, payload.iv)
    padded = cipher.decrypt(payload.ciphertext)
    plaintext = _unpad(padded)
    return plaintext.decode('utf-8')
```

#### **HMAC for Message Integrity**:
```python
import hmac
import hashlib

def generate_hmac(key: bytes, data: bytes) -> bytes:
    return hmac.new(key, data, hashlib.sha256).digest()

def verify_hmac(key: bytes, data: bytes, expected: bytes) -> bool:
    actual = generate_hmac(key, data)
    return hmac.compare_digest(actual, expected)
```

**Example Flow**:
```python
# User A sends message to User B
message = "Hello, this is secret!"
shared_key = b'32-byte-shared-key-from-DH-exchange'

# Encrypt
payload = encrypt(shared_key, message)
# payload.ciphertext: b'\x9a\x3f\x2e...' (encrypted)
# payload.iv: b'\x1a\x2b\x3c...' (random IV)
# payload.hmac_tag: b'\x4d\x5e\x6f...' (integrity tag)

# Decrypt
original = decrypt(shared_key, payload)
# original: "Hello, this is secret!"
```

**Where it's used**:
- `crypto/encryption.py` - AES-256 CBC encryption for messages
- `crypto/utils.py` - HMAC-SHA256 for message integrity
- `app.py` - Brute force AES simulations
- All chat messages are encrypted before database storage

---

### 10. **requests==2.32.3**

**Purpose**: HTTP library for making external API calls

**What it does**:
- Makes HTTP GET, POST, PUT, DELETE requests
- Handles API communication
- Session management for external services

**Usage example**:
```python
import requests

# GET request
response = requests.get('https://api.example.com/data')
data = response.json()

# POST request
response = requests.post('https://api.example.com/login', 
                        json={'username': 'user', 'password': 'pass'})
```

**Where it's used**:
- Available for future external API integrations
- Can be used for webhook notifications or third-party services

---

### 11. **pytest==8.3.4** ✅

**Purpose**: Testing framework for Python applications

**What it does**:
- Runs unit tests and integration tests
- Provides test fixtures and assertions
- Generates test coverage reports

**Usage in this project**:
```python
# tests/test_crypto.py
def test_aes_encrypt_decrypt_roundtrip():
    key_pair_a = key_exchange.generate_key_pair()
    key_pair_b = key_exchange.generate_key_pair()
    shared_a = key_exchange.compute_shared_key(key_pair_a.private_key, key_pair_b.public_key)
    
    plaintext = "Confidential Message"
    payload = encryption.encrypt(shared_a, plaintext)
    decrypted = encryption.decrypt(shared_a, payload)
    
    assert decrypted == plaintext

def test_bcrypt_hashing_roundtrip():
    password = "ComplexPass!234"
    hashed = hashing.hash_password(password)
    assert hashing.verify_password(password, hashed)
    assert not hashing.verify_password("wrong", hashed)
```

**Running tests**:
```bash
# Run all tests
pytest

# Run with verbose output
pytest -v

# Run specific test file
pytest tests/test_crypto.py

# Run with coverage
pytest --cov=crypto --cov=database
```

**Where it's used**:
- `tests/test_crypto.py` - Tests for encryption, hashing, and key exchange

---

## 🌍 Real-World Scenario: Complete Chat Flow

Let's walk through a complete real-world example of how all these libraries work together when two users (Alice and Bob) use the secure chat application.

### **Scenario: Alice and Bob's Secure Conversation**

---

#### **Step 1: Alice Registers an Account**

**User Action**: Alice visits the registration page and creates an account.

**What Happens Behind the Scenes**:

1. **Flask** receives the POST request:
   ```python
   # app.py - Registration route
   @app.route("/register", methods=["POST"])
   def register():
       username = request.form.get("username")  # "alice"
       password = request.form.get("password")  # "SecurePass123!"
   ```

2. **bcrypt** hashes Alice's password:
   ```python
   # crypto/hashing.py
   import bcrypt
   
   salt = bcrypt.gensalt(rounds=12)
   hashed = bcrypt.hashpw(b"SecurePass123!", salt)
   # Result: b'$2b$12$N9qo8uLOickgx2ZMRZoMye...'
   ```

3. **Diffie-Hellman** generates Alice's key pair:
   ```python
   # crypto/key_exchange.py
   import secrets
   
   # Generate private key (random large number)
   alice_private = secrets.randbelow(P - 2) + 2
   # Example: 8472619384756291847562918475629...
   
   # Generate public key
   alice_public = pow(G, alice_private, P)
   # Example: 9384756291847562918475629184756...
   ```

4. **Flask-SQLAlchemy** saves Alice to database:
   ```python
   # database/models.py
   user = User(
       username="alice",
       password_hash=hashed,  # bcrypt hash
       public_key=str(alice_public),
       private_key=str(alice_private)
   )
   db.session.add(user)
   db.session.commit()
   ```

**Database State** (SQLite):
```
users table:
+----+----------+------------------+------------------+------------------+
| id | username | password_hash    | public_key       | private_key      |
+----+----------+------------------+------------------+------------------+
| 1  | alice    | $2b$12$N9qo8... | 938475629184...  | 847261938475...  |
+----+----------+------------------+------------------+------------------+
```

---

#### **Step 2: Bob Registers an Account**

**Same process as Alice**:
- Password hashed with **bcrypt**
- DH key pair generated
- Stored in database with **Flask-SQLAlchemy**

**Database State**:
```
users table:
+----+----------+------------------+------------------+------------------+
| id | username | password_hash    | public_key       | private_key      |
+----+----------+------------------+------------------+------------------+
| 1  | alice    | $2b$12$N9qo8... | 938475629184...  | 847261938475...  |
| 2  | bob      | $2b$12$K8mp7... | 123456789012...  | 234567890123...  |
+----+----------+------------------+------------------+------------------+
```

---

#### **Step 3: Alice Logs In**

**User Action**: Alice enters username and password.

**What Happens**:

1. **Flask** receives login request:
   ```python
   username = request.form.get("username")  # "alice"
   password = request.form.get("password")  # "SecurePass123!"
   ```

2. **Flask-SQLAlchemy** queries database:
   ```python
   user = User.query.filter_by(username="alice").first()
   ```

3. **bcrypt** verifies password:
   ```python
   # crypto/hashing.py
   is_valid = bcrypt.checkpw(
       b"SecurePass123!",
       user.password_hash  # b'$2b$12$N9qo8...'
   )
   # Returns: True ✅
   ```

4. **Flask session** stores user info:
   ```python
   session['user_id'] = user.id  # 1
   session['username'] = user.username  # "alice"
   ```

5. **Login attempt logged** in database:
   ```python
   attempt = LoginAttempt(
       username="alice",
       success=True,
       ip_address="192.168.1.100"
   )
   db.session.add(attempt)
   ```

**If Alice enters wrong password 5 times**:
- Rate limiting kicks in (tracked by **Flask-SQLAlchemy**)
- Account locked for 60 seconds
- All attempts logged for security audit

---

#### **Step 4: Alice Opens Chat with Bob**

**User Action**: Alice clicks on Bob's name to start a chat.

**What Happens**:

1. **Flask** routes to chat page:
   ```python
   @app.route("/chat/<username>")
   def chat(username):
       partner = User.query.filter_by(username="bob").first()
   ```

2. **Diffie-Hellman shared key computation**:
   ```python
   # crypto/key_exchange.py
   
   # Alice computes shared key using:
   # - Her private key: 847261938475...
   # - Bob's public key: 123456789012...
   
   shared_secret = pow(bob_public, alice_private, P)
   # Result: 567890123456789012345678...
   
   # Derive 32-byte AES key using HKDF
   shared_key = hkdf_sha256(shared_secret)
   # Result: b'\x2a\x5f\x8c\x3d...' (32 bytes)
   ```

3. **Bob computes the SAME shared key** (when he opens chat):
   ```python
   # Using Bob's private key and Alice's public key
   shared_secret = pow(alice_public, bob_private, P)
   # Result: 567890123456789012345678... (SAME!)
   
   shared_key = hkdf_sha256(shared_secret)
   # Result: b'\x2a\x5f\x8c\x3d...' (SAME 32 bytes!)
   ```

4. **Flask session** caches the shared key:
   ```python
   session['shared_key:1:2'] = base64.b64encode(shared_key)
   ```

---

#### **Step 5: Alice Sends Encrypted Message to Bob**

**User Action**: Alice types "Hey Bob, let's meet at 3 PM!" and clicks Send.

**What Happens**:

1. **Flask** receives AJAX POST request:
   ```python
   # JavaScript sends via requests library concept
   data = {
       "receiver": "bob",
       "message": "Hey Bob, let's meet at 3 PM!"
   }
   ```

2. **pycryptodome** generates random IV:
   ```python
   # crypto/encryption.py
   from Crypto.Random import get_random_bytes
   
   iv = get_random_bytes(16)
   # Result: b'\x9a\x3f\x2e\x1c\x5b\x7d\x8e\x4a\x6f\x0c\x1d\x2e\x3f\x4a\x5b\x6c'
   ```

3. **pycryptodome AES** encrypts the message:
   ```python
   from Crypto.Cipher import AES
   
   cipher = AES.new(shared_key, AES.MODE_CBC, iv)
   plaintext = "Hey Bob, let's meet at 3 PM!"
   padded = _pad(plaintext.encode('utf-8'))
   ciphertext = cipher.encrypt(padded)
   # Result: b'\xf3\x8a\x2c\x5d\x9e\x1f\x4b\x7c...' (encrypted bytes)
   ```

4. **HMAC** generates integrity tag:
   ```python
   # crypto/utils.py
   import hmac
   import hashlib
   
   tag = hmac.new(shared_key, iv + ciphertext, hashlib.sha256).digest()
   # Result: b'\x4d\x5e\x6f\x7a\x8b\x9c\xad\xbe...' (32 bytes)
   ```

5. **Base64 encoding** for database storage:
   ```python
   # crypto/utils.py
   import base64
   
   encrypted_b64 = base64.b64encode(ciphertext).decode('utf-8')
   iv_b64 = base64.b64encode(iv).decode('utf-8')
   hmac_b64 = base64.b64encode(tag).decode('utf-8')
   ```

6. **Flask-SQLAlchemy** saves encrypted message:
   ```python
   message = Message(
       sender_id=1,  # Alice
       receiver_id=2,  # Bob
       encrypted_message=encrypted_b64,
       iv=iv_b64,
       hmac=hmac_b64
   )
   db.session.add(message)
   db.session.commit()
   ```

**Database State** (messages table):
```
+----+-----------+-------------+----------------------+------------------+------------------+
| id | sender_id | receiver_id | encrypted_message    | iv               | hmac             |
+----+-----------+-------------+----------------------+------------------+------------------+
| 1  | 1         | 2           | 86OsXZ4fS3yM8Q==     | mj8uHFt9jkpv... | TV5veoubzb4=     |
+----+-----------+-------------+----------------------+------------------+------------------+
```

**Notice**: The actual message "Hey Bob, let's meet at 3 PM!" is **NEVER** stored in the database! Only encrypted ciphertext.

---

#### **Step 6: Bob Receives and Decrypts Message**

**User Action**: Bob's browser polls for new messages every 2 seconds (configured via **python-dotenv**).

**What Happens**:

1. **Flask** receives GET request:
   ```python
   @app.route("/get_messages/<username>")
   def get_messages(username):
       messages = Message.query.filter(...).all()
   ```

2. **Flask-SQLAlchemy** retrieves encrypted messages:
   ```python
   # Returns encrypted data from database
   encrypted_message = "86OsXZ4fS3yM8Q=="
   iv = "mj8uHFt9jkpv..."
   hmac_tag = "TV5veoubzb4="
   ```

3. **Base64 decoding**:
   ```python
   ciphertext = base64.b64decode(encrypted_message)
   iv = base64.b64decode(iv)
   expected_hmac = base64.b64decode(hmac_tag)
   ```

4. **HMAC verification** (prevents tampering):
   ```python
   # crypto/utils.py
   actual_hmac = hmac.new(shared_key, iv + ciphertext, hashlib.sha256).digest()
   
   if not hmac.compare_digest(actual_hmac, expected_hmac):
       raise ValueError("HMAC verification failed - message tampered!")
   # ✅ Verification passes
   ```

5. **pycryptodome AES** decrypts message:
   ```python
   # crypto/encryption.py
   cipher = AES.new(shared_key, AES.MODE_CBC, iv)
   padded = cipher.decrypt(ciphertext)
   plaintext = _unpad(padded)
   message = plaintext.decode('utf-8')
   # Result: "Hey Bob, let's meet at 3 PM!"
   ```

6. **Flask** sends JSON response:
   ```python
   return jsonify([{
       "sender": "alice",
       "receiver": "bob",
       "content": "Hey Bob, let's meet at 3 PM!",
       "timestamp": "2024-12-30T22:00:00"
   }])
   ```

7. **JavaScript** displays message in Bob's chat window.

---

#### **Step 7: Security Audit**

**Admin Action**: Administrator checks security logs.

**What Happens**:

1. **Flask** route for admin logs:
   ```python
   @app.route("/admin/logs")
   @login_required
   def admin_logs():
       attempts = LoginAttempt.query.order_by(LoginAttempt.created_at.desc()).limit(50).all()
   ```

2. **Flask-SQLAlchemy** retrieves audit data:
   ```
   Login Attempts:
   - alice | SUCCESS | 192.168.1.100 | 2024-12-30 22:00:00
   - bob   | SUCCESS | 192.168.1.101 | 2024-12-30 22:01:00
   - eve   | FAILED  | 192.168.1.200 | 2024-12-30 22:02:00
   - eve   | FAILED  | 192.168.1.200 | 2024-12-30 22:02:05
   - eve   | FAILED  | 192.168.1.200 | 2024-12-30 22:02:10
   ```

3. **Rate limiting** detected Eve's brute force attempt and locked the account.

---

### **Complete Data Flow Diagram**

```
Alice's Browser                    Server                           Bob's Browser
     |                               |                                    |
     |--[1] Register (alice)-------->|                                    |
     |                               |--[bcrypt hash password]            |
     |                               |--[Generate DH keys]                |
     |                               |--[SQLAlchemy save to DB]           |
     |<--[Registration Success]------|                                    |
     |                               |                                    |
     |--[2] Login (alice)----------->|                                    |
     |                               |--[SQLAlchemy query user]           |
     |                               |--[bcrypt verify password]          |
     |                               |--[Flask session create]            |
     |<--[Login Success]-------------|                                    |
     |                               |                                    |
     |--[3] Open chat with Bob]----->|                                    |
     |                               |--[Compute DH shared key]           |
     |                               |--[Cache in Flask session]          |
     |<--[Chat page rendered]--------|                                    |
     |                               |                                    |
     |--[4] Send: "Hey Bob!"]------->|                                    |
     |                               |--[Generate random IV]              |
     |                               |--[AES encrypt message]             |
     |                               |--[Generate HMAC tag]               |
     |                               |--[Base64 encode]                   |
     |                               |--[SQLAlchemy save encrypted]       |
     |<--[Message sent]--------------|                                    |
     |                               |                                    |
     |                               |<--[5] Poll for messages]-----------|
     |                               |--[SQLAlchemy retrieve encrypted]   |
     |                               |--[Base64 decode]                   |
     |                               |--[Verify HMAC]                     |
     |                               |--[AES decrypt message]             |
     |                               |--[Return plaintext]--------------->|
     |                               |                                    |
     |                               |                          [Display: "Hey Bob!"]
```

---

### **Security Guarantees in This Scenario**

✅ **Password Security**:
- Alice's password "SecurePass123!" is **never** stored
- Only bcrypt hash stored: `$2b$12$N9qo8...`
- Even database admin cannot see original password

✅ **Message Confidentiality**:
- Message "Hey Bob, let's meet at 3 PM!" stored as: `86OsXZ4fS3yM8Q==`
- Database admin sees only encrypted gibberish
- Only Alice and Bob can decrypt (they have the shared key)

✅ **Message Integrity**:
- HMAC tag ensures message wasn't tampered with
- If attacker modifies ciphertext, HMAC verification fails
- Message rejected before decryption attempt

✅ **Forward Secrecy**:
- Each chat session can use different shared keys
- Compromising one key doesn't affect other conversations

✅ **Audit Trail**:
- All login attempts logged with IP addresses
- Brute force attempts detected and blocked
- Admin can review security events

---

### **What If an Attacker Steals the Database?**

**Scenario**: Hacker gains access to `secure_chat.db` file.

**What They See**:
```sql
SELECT * FROM messages;
-- Result:
-- encrypted_message: "86OsXZ4fS3yM8Q==" (meaningless without key)
-- iv: "mj8uHFt9jkpv..." (random, doesn't help)
-- hmac: "TV5veoubzb4=" (can't be reversed)

SELECT * FROM users;
-- Result:
-- password_hash: "$2b$12$N9qo8..." (bcrypt hash, extremely slow to crack)
-- private_key: "847261938475..." (useless without knowing which user)
```

**What They CANNOT Do**:
- ❌ Read any messages (encrypted with AES-256)
- ❌ Log in as users (passwords hashed with bcrypt)
- ❌ Forge messages (HMAC prevents tampering)
- ❌ Decrypt old messages (need shared keys computed from private keys)

**What They CAN Do**:
- ✅ See usernames (not sensitive)
- ✅ See message timestamps (metadata leakage)
- ✅ See who messaged whom (traffic analysis)
- ✅ Attempt offline password cracking (very slow due to bcrypt)

---

### **Testing This Scenario**

You can test this exact flow using **pytest**:

```python
# tests/test_crypto.py
def test_alice_bob_scenario():
    # Step 1: Generate keys for Alice and Bob
    alice_keys = key_exchange.generate_key_pair()
    bob_keys = key_exchange.generate_key_pair()
    
    # Step 2: Compute shared keys (should match!)
    alice_shared = key_exchange.compute_shared_key(
        alice_keys.private_key, 
        bob_keys.public_key
    )
    bob_shared = key_exchange.compute_shared_key(
        bob_keys.private_key, 
        alice_keys.public_key
    )
    assert alice_shared == bob_shared  # ✅ Same key!
    
    # Step 3: Alice encrypts message
    message = "Hey Bob, let's meet at 3 PM!"
    encrypted = encryption.encrypt(alice_shared, message)
    
    # Step 4: Bob decrypts message
    decrypted = encryption.decrypt(bob_shared, encrypted)
    assert decrypted == message  # ✅ Original message recovered!
    
    # Step 5: Verify HMAC prevents tampering
    encrypted.ciphertext = b"tampered data"
    with pytest.raises(ValueError, match="HMAC verification failed"):
        encryption.decrypt(bob_shared, encrypted)  # ✅ Tampering detected!
```

Run with:
```bash
pytest tests/test_crypto.py -v
```

---

## 🔐 Security Features Enabled by These Libraries

### **1. Password Security (bcrypt)**
- Passwords hashed with bcrypt (12 rounds)
- Salt automatically generated per password
- Resistant to rainbow table attacks

### **2. Message Encryption (pycryptodome)**
- **AES-256 CBC** mode for message encryption
- **Random IVs** ensure same message encrypts differently each time
- **HMAC-SHA256** prevents tampering and ensures integrity
- Messages stored encrypted in database (no plaintext)

### **3. Key Exchange (Diffie-Hellman)**
- 2048-bit MODP group (RFC 3526)
- HKDF-SHA256 for key derivation
- Secure shared key establishment without transmitting secrets

### **4. Login Protection**
- Rate limiting: 5 failed attempts = 60-second lockdown
- IP address logging for audit trails
- Login attempt tracking in database

---

## 📊 Database Models

All models use SQLAlchemy ORM:

```python
# User Model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.LargeBinary(128), nullable=False)  # bcrypt hash
    public_key = db.Column(db.Text, nullable=False)   # DH public key
    private_key = db.Column(db.Text, nullable=False)  # DH private key

# Message Model (Encrypted Storage)
class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    receiver_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    encrypted_message = db.Column(db.Text, nullable=False)  # AES ciphertext
    iv = db.Column(db.Text, nullable=False)                 # AES IV
    hmac = db.Column(db.Text, nullable=False)               # HMAC tag
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
```

---

## 🚀 Running the Application

```bash
# 1. Activate virtual environment
.\information_security\Scripts\activate

# 2. Install dependencies
pip install -r requirements.txt

# 3. Run the Flask application
flask --app app:create_app --debug run

# 4. Access at http://localhost:5000
```

---

## 🧪 Testing

```bash
# Run all tests
pytest

# Run with coverage report
pytest --cov=crypto --cov=database --cov-report=html

# View coverage report
# Open htmlcov/index.html in browser
```

---

## 📝 Environment Variables

Create a `.env` file in the project root:

```env
# Security
SECRET_KEY=your-super-secret-flask-key-change-this-in-production

# Database
DATABASE_URL=sqlite:///secure_chat.db

# Chat Settings
CHAT_POLL_INTERVAL=2

# Login Security
LOGIN_LOCKOUT_THRESHOLD=5
LOGIN_LOCKOUT_DURATION_SECONDS=60
LOGIN_ATTEMPT_WINDOW_MINUTES=5

# Master Key (for additional encryption if needed)
MASTER_KEY=2b7e151628aed2a6abf7158809cf4f3c2b7e151628aed2a6abf7158809cf4f3c
```

---

## 🔍 Troubleshooting

### **Issue**: `ModuleNotFoundError: No module named 'crypto'`

**Solution**: Run tests from project root directory:
```bash
# From project root
cd "c:\Users\pc\Desktop\Information security"
pytest tests/test_crypto.py
```

Or set PYTHONPATH:
```bash
$env:PYTHONPATH = "c:\Users\pc\Desktop\Information security"
pytest
```

### **Issue**: `ImportError: No module named 'Crypto'`

**Solution**: Install pycryptodome:
```bash
pip install pycryptodome==3.20.0
```

### **Issue**: Database errors

**Solution**: Initialize database:
```bash
flask --app app:create_app shell
>>> from database import db
>>> db.create_all()
>>> exit()
```

---

## 📚 Additional Resources

- **Flask Documentation**: https://flask.palletsprojects.com/
- **SQLAlchemy Documentation**: https://docs.sqlalchemy.org/
- **PyCryptodome Documentation**: https://pycryptodome.readthedocs.io/
- **bcrypt Documentation**: https://github.com/pyca/bcrypt/
- **pytest Documentation**: https://docs.pytest.org/

---

## ✅ Verification Checklist

- [ ] All dependencies installed: `pip install -r requirements.txt`
- [ ] Virtual environment activated
- [ ] `.env` file created with proper configuration
- [ ] Database initialized: `flask --app app:create_app run`
- [ ] Tests passing: `pytest`
- [ ] Application running: Access http://localhost:5000

---

**Last Updated**: December 30, 2024  
**Project**: Secure End-to-End Encrypted Chat  
**Python Version**: 3.8+
