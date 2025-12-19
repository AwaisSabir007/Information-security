"""
Utility script to show how chats are stored in encrypted form.

Run: python scripts/chat_database_report.py
"""

from __future__ import annotations

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app import create_app
from crypto import utils
from database.models import Message, User

app = create_app()


def _format_message_row(message: Message) -> str:
    sender = User.query.get(message.sender_id)
    receiver = User.query.get(message.receiver_id)
    cipher_preview = message.encrypted_message[:60] + ("..." if len(message.encrypted_message) > 60 else "")
    iv_preview = message.iv[:32] + ("..." if len(message.iv) > 32 else "")
    hmac_preview = message.hmac[:64] + ("..." if len(message.hmac) > 64 else "")

    lines = [
        f"Message ID     : {message.id}",
        f"Timestamp      : {message.timestamp.isoformat()}",
        f"Participants   : {sender.username} -> {receiver.username}",
        f"Ciphertext (b64): {cipher_preview}",
        f"IV (b64)       : {iv_preview}",
        f"HMAC (b64)     : {hmac_preview}",
        f"HMAC length    : {len(utils.decode_bytes(message.hmac))} bytes (SHA-256)",
    ]
    return "\n".join(lines)


def main() -> None:
    with app.app_context():
        messages = Message.query.order_by(Message.timestamp.asc()).all()
        if not messages:
            print("No chat messages stored yet. Send a message through the UI first.")
            return

        print("=== Secure Chat Database Snapshot ===")
        print(f"Total messages stored: {len(messages)}")
        print("Note: Ciphertext, IV, and HMAC are Base64 strings in the database.")
        print("Plaintext never touches the database; only encrypted payloads are persisted.\n")

        for message in messages:
            print(_format_message_row(message))
            print("-" * 72)

        unique_hmacs = {message.hmac for message in messages}
        print(f"Unique HMAC tags (should equal messages): {len(unique_hmacs)}")
        print("Each message has its own HMAC-SHA256 tag ensuring tamper detection.")


if __name__ == "__main__":
    main()

