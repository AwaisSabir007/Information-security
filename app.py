from __future__ import annotations

import json
import time
from datetime import datetime, timedelta
from functools import wraps

from Crypto.Cipher import AES as CryptoAES

from flask import (
    Flask,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
    flash,
)
from sqlalchemy import and_, or_
from sqlalchemy.exc import IntegrityError

from config import Config
from crypto import encryption, hashing, key_exchange, utils
from crypto.encryption import EncryptedPayload
from database import db
from database.models import BruteForceLog, LoginAttempt, Message, User


def create_app(config_class: type[Config] = Config) -> Flask:
    app = Flask(__name__)
    app.config.from_object(config_class)

    db.init_app(app)

    with app.app_context():
        db.create_all()

    register_routes(app)
    return app


def current_user() -> User | None:
    user_id = session.get("user_id")
    if not user_id:
        return None
    return User.query.get(user_id)


def login_required(view_func):
    @wraps(view_func)
    def wrapped(*args, **kwargs):
        if not current_user():
            flash("Please login to continue.", "warning")
            return redirect(url_for("login"))
        return view_func(*args, **kwargs)

    return wrapped


def store_login_attempt(username: str, success: bool, ip: str | None = None) -> None:
    attempt = LoginAttempt(username=username, success=success, ip_address=ip)
    db.session.add(attempt)
    db.session.commit()


def lockout_remaining_seconds(username: str, app: Flask) -> int:
    if not username:
        return 0
    threshold = app.config["LOGIN_LOCKOUT_THRESHOLD"]
    duration = app.config["LOGIN_LOCKOUT_DURATION_SECONDS"]
    window_minutes = app.config["LOGIN_ATTEMPT_WINDOW_MINUTES"]

    now = datetime.utcnow()
    window_start = now - timedelta(minutes=window_minutes)

    base_query = LoginAttempt.query.filter(
        LoginAttempt.username == username,
        LoginAttempt.success.is_(False),
        LoginAttempt.created_at >= window_start,
    )

    failure_count = base_query.count()
    if failure_count < threshold:
        return 0

    last_attempt = (
        base_query.order_by(LoginAttempt.created_at.desc()).first()
    ).created_at
    expires_at = last_attempt + timedelta(seconds=duration)
    remaining = (expires_at - now).total_seconds()
    return int(remaining) if remaining > 0 else 0


def _session_key(user_a: int, user_b: int) -> str:
    return f"shared_key:{min(user_a, user_b)}:{max(user_a, user_b)}"


def get_shared_key_for_users(user_a: User, user_b: User) -> bytes:
    key_name = _session_key(user_a.id, user_b.id)
    cached = session.get(key_name)
    if cached:
        return utils.decode_bytes(cached)

    private_key = int(user_a.private_key)
    peer_public = int(user_b.public_key)
    shared_key = key_exchange.compute_shared_key(private_key, peer_public)
    session[key_name] = utils.encode_bytes(shared_key)
    session.modified = True
    return shared_key


def register_routes(app: Flask) -> None:
    @app.route("/")
    def index():
        if current_user():
            return redirect(url_for("chat_list"))
        return redirect(url_for("login"))

    @app.route("/register", methods=["GET", "POST"])
    def register():
        if request.method == "POST":
            username = request.form.get("username", "").strip()
            password = request.form.get("password", "")
            confirm_password = request.form.get("confirm_password", "")
            if not username or not password:
                flash("Username and password are required.", "danger")
                return redirect(url_for("register"))
            if password != confirm_password:
                flash("Passwords do not match.", "danger")
                return redirect(url_for("register"))
            if len(password) < 8:
                flash("Password must be at least 8 characters long.", "danger")
                return redirect(url_for("register"))

            # Check for special characters
            special_characters = set("!@#$%^&*()-_=+[]{}|;:,.<>?/")
            if not any(char in special_characters for char in password):
                flash("Password must contain at least one special character (e.g., ! @ # $).", "danger")
                return redirect(url_for("register"))

            hashed = hashing.hash_password(password)
            key_pair = key_exchange.generate_key_pair()

            user = User(
                username=username,
                password_hash=hashed,
                public_key=str(key_pair.public_key),
                private_key=str(key_pair.private_key),
            )
            db.session.add(user)
            try:
                db.session.commit()
            except IntegrityError:
                db.session.rollback()
                flash("Username already exists.", "warning")
                return redirect(url_for("register"))

            flash("Registration successful. Please login.", "success")
            return redirect(url_for("login"))

        return render_template("register.html")

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if request.method == "POST":
            username = request.form.get("username", "").strip()
            password = request.form.get("password", "")

            lockout_seconds = lockout_remaining_seconds(username, app)
            if lockout_seconds > 0:
                flash(
                    f"Too many failed attempts. Please wait {lockout_seconds} seconds before trying again.",
                    "danger",
                )
                return redirect(url_for("login"))

            user = User.query.filter_by(username=username).first()

            if not user or not hashing.verify_password(password, user.password_hash):
                store_login_attempt(username, False, request.remote_addr)
                remaining = lockout_remaining_seconds(username, app)
                if remaining > 0:
                    flash(
                        f"Too many failed attempts. Please wait {remaining} seconds before trying again.",
                        "danger",
                    )
                else:
                    flash("Invalid credentials.", "danger")
                return redirect(url_for("login"))

            session.clear()
            session["user_id"] = user.id
            session["username"] = user.username
            store_login_attempt(username, True, request.remote_addr)
            flash("Logged in successfully.", "success")
            return redirect(url_for("chat_list"))

        return render_template("login.html")

    @app.route("/logout")
    def logout():
        session.clear()
        flash("You have been logged out.", "info")
        return redirect(url_for("login"))

    @app.route("/chat")
    @login_required
    def chat_list():
        user = current_user()
        users = User.query.filter(User.id != user.id).all()
        return render_template("chat_list.html", users=users)

    @app.route("/chat/<string:username>")
    @login_required
    def chat(username: str):
        user = current_user()
        partner = User.query.filter_by(username=username).first_or_404()
        contacts = User.query.filter(User.id != user.id).all()
        get_shared_key_for_users(user, partner)
        return render_template(
            "chat.html",
            partner=partner,
            contacts=contacts,
            current_user=user,
            poll_interval=app.config["CHAT_POLL_INTERVAL"],
        )

    @app.route("/send_message", methods=["POST"])
    @login_required
    def send_message():
        user = current_user()
        data = request.get_json()
        receiver_username = data.get("receiver")
        plaintext = data.get("message", "").strip()

        if not plaintext:
            return jsonify({"error": "Message cannot be empty."}), 400

        receiver = User.query.filter_by(username=receiver_username).first()
        if not receiver:
            return jsonify({"error": "Receiver not found."}), 404

        shared_key = get_shared_key_for_users(user, receiver)
        payload = encryption.encrypt(shared_key, plaintext)

        message = Message(
            sender_id=user.id,
            receiver_id=receiver.id,
            encrypted_message=utils.encode_bytes(payload.ciphertext),
            iv=utils.encode_bytes(payload.iv),
            hmac=utils.encode_bytes(payload.hmac_tag),
        )
        db.session.add(message)
        db.session.commit()

        return jsonify({"status": "sent"})

    @app.route("/get_messages/<string:username>")
    @login_required
    def get_messages(username: str):
        user = current_user()
        partner = User.query.filter_by(username=username).first_or_404()
        shared_key = get_shared_key_for_users(user, partner)

        messages = (
            Message.query.filter(
                or_(
                    and_(Message.sender_id == user.id, Message.receiver_id == partner.id),
                    and_(Message.sender_id == partner.id, Message.receiver_id == user.id),
                )
            )
            .order_by(Message.timestamp.asc())
            .all()
        )

        serialized = []
        for message in messages:
            payload = EncryptedPayload(
                ciphertext=utils.decode_bytes(message.encrypted_message),
                iv=utils.decode_bytes(message.iv),
                hmac_tag=utils.decode_bytes(message.hmac),
            )
            try:
                plaintext = encryption.decrypt(shared_key, payload)
            except ValueError:
                plaintext = "[HMAC verification failed]"

            serialized.append(
                {
                    "id": message.id,
                    "sender": message.sender_user.username,
                    "receiver": message.receiver_user.username,
                    "content": plaintext,
                    "timestamp": message.timestamp.isoformat(),
                }
            )

        return jsonify(serialized)

    @app.route("/brute_force", methods=["GET"])
    @login_required
    def brute_force_home():
        return render_template("brute_force.html")

    @app.route("/bruteforce_password", methods=["POST"])
    @login_required
    def brute_force_password():
        bcrypt_hash = request.form.get("bcrypt_hash", "").strip()
        dictionary_words = request.form.get("dictionary", "").splitlines()
        dictionary_words = [word.strip() for word in dictionary_words if word.strip()]

        if not bcrypt_hash or not dictionary_words:
            flash("Provide a bcrypt hash and at least one dictionary word.", "warning")
            return redirect(url_for("brute_force_home"))

        start = time.perf_counter()
        attempts = 0
        found = None

        for word in dictionary_words:
            attempts += 1
            if hashing.verify_password(word, bcrypt_hash.encode("utf-8")):
                found = word
                break

        duration_ms = (time.perf_counter() - start) * 1000
        result = "success" if found else "failure"

        db.session.add(
            BruteForceLog(
                attack_type="password",
                attempts=attempts,
                duration_ms=duration_ms,
                result=result,
            )
        )
        db.session.commit()

        flash(
            f"Password brute force {result}. Attempts: {attempts}, Time: {duration_ms:.2f}ms.",
            "info",
        )
        return redirect(url_for("brute_force_home"))

    @app.route("/bruteforce_key", methods=["POST"])
    @login_required
    def brute_force_key():
        plaintext = request.form.get("plaintext", "Test message")
        bit_size = int(request.form.get("bit_size", 16))
        max_key = 2**bit_size

        actual_key = int(request.form.get("known_key", 42)) % max_key
        iv = b"\x00" * 16
        target_cipher = _mini_aes_encrypt(actual_key, plaintext.encode("utf-8"), iv)

        start = time.perf_counter()
        found_key = None
        for key_candidate in range(max_key):
            if _mini_aes_encrypt(key_candidate, plaintext.encode("utf-8"), iv) == target_cipher:
                found_key = key_candidate
                break
        duration_ms = (time.perf_counter() - start) * 1000

        db.session.add(
            BruteForceLog(
                attack_type="aes",
                attempts=(found_key + 1) if found_key is not None else max_key,
                duration_ms=duration_ms,
                result="success" if found_key is not None else "failure",
            )
        )
        db.session.commit()

        flash(
            f"Simulated AES brute force complete. Key found: {found_key}, Time: {duration_ms:.2f}ms.",
            "info",
        )
        return redirect(url_for("brute_force_home"))

    @app.route("/admin/logs")
    @login_required
    def admin_logs():
        attempts = LoginAttempt.query.order_by(LoginAttempt.created_at.desc()).limit(50).all()
        brute_logs = BruteForceLog.query.order_by(BruteForceLog.created_at.desc()).limit(50).all()
        return render_template("admin_logs.html", attempts=attempts, brute_logs=brute_logs)

    @app.route("/hacker/dashboard")
    @login_required
    def hacker_dashboard():
        """Render the Hacker View dashboard."""
        return render_template("hacker_dashboard.html")

    @app.route("/api/sniffer")
    @login_required
    def api_sniffer():
        """API to return the latest encrypted messages for the sniffer view."""
        # Fetch the last 20 messages from all users
        messages = (
            Message.query.order_by(Message.timestamp.desc())
            .limit(20)
            .all()
        )
        
        packet_data = []
        for msg in messages:
            # Note: msg.encrypted_message is already the base64 string in the DB.
            # We don't need to decode it to bytes just to display it.
            # Ideally we show the raw ciphertext, but for the "hacker view" the base64 string is perfect.
            
            packet_data.append({
                "id": msg.id,
                "timestamp": msg.timestamp.strftime("%H:%M:%S"),
                "source_ip": "192.168.1." + str(100 + msg.sender_id), 
                "dest_ip": "192.168.1." + str(100 + msg.receiver_id),
                "protocol": "TLSv1.3",
                "length": len(msg.encrypted_message),
                "encrypted_payload": msg.encrypted_message[:50] + "...",
                "iv": msg.iv[:20] + "..." if msg.iv else "",
                "hmac": msg.hmac[:20] + "..." if msg.hmac else "",
                "type": "ENCRYPTED_DATA"
            })
            
        return jsonify(packet_data)


def _mini_aes_key(key: int) -> bytes:
    key_bytes = key.to_bytes(2, byteorder="big", signed=False)
    return (key_bytes * 16)[:32]


def _mini_aes_encrypt(key: int, plaintext: bytes, iv: bytes) -> bytes:
    cipher_key = _mini_aes_key(key)
    cipher = CryptoAES.new(cipher_key, CryptoAES.MODE_CBC, iv)
    pad_len = 16 - (len(plaintext) % 16)
    if pad_len == 0:
        pad_len = 16
    padded = plaintext + bytes([pad_len] * pad_len)
    return cipher.encrypt(padded)


if __name__ == "__main__":
    application = create_app()
    application.run(debug=True)

