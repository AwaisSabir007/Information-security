"""
Simple script to view the contents of secure_chat.db database
"""
import sqlite3
from datetime import datetime

def view_database():
    try:
        # Connect to database
        conn = sqlite3.connect('secure_chat.db')
        cursor = conn.cursor()
        
        print("=" * 80)
        print("SECURE CHAT DATABASE VIEWER")
        print("=" * 80)
        
        # Check if database has tables
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = cursor.fetchall()
        
        if not tables:
            print("\n❌ Database is empty! No tables found.")
            print("\n💡 To create the database, run the Flask app first:")
            print("   flask --app app:create_app run")
            conn.close()
            return
        
        print(f"\n📊 Found {len(tables)} tables: {', '.join([t[0] for t in tables])}\n")
        
        # View Users Table
        print("\n" + "=" * 80)
        print("👥 USERS TABLE (Login Information)")
        print("=" * 80)
        cursor.execute("SELECT id, username, created_at FROM users")
        users = cursor.fetchall()
        
        if users:
            print(f"\nTotal Users: {len(users)}\n")
            for user in users:
                print(f"  ID: {user[0]}")
                print(f"  Username: {user[1]}")
                print(f"  Created: {user[2]}")
                print(f"  {'-' * 70}")
        else:
            print("\n  No users registered yet.")
        
        # View Messages Table
        print("\n" + "=" * 80)
        print("💬 MESSAGES TABLE (Encrypted Chats)")
        print("=" * 80)
        cursor.execute("""
            SELECT m.id, u1.username as sender, u2.username as receiver, 
                   substr(m.encrypted_message, 1, 40) as cipher_preview,
                   m.timestamp
            FROM messages m
            JOIN users u1 ON m.sender_id = u1.id
            JOIN users u2 ON m.receiver_id = u2.id
            ORDER BY m.timestamp DESC
            LIMIT 10
        """)
        messages = cursor.fetchall()
        
        if messages:
            print(f"\nTotal Messages: ", end="")
            cursor.execute("SELECT COUNT(*) FROM messages")
            print(f"{cursor.fetchone()[0]} (showing last 10)\n")
            
            for msg in messages:
                print(f"  Message ID: {msg[0]}")
                print(f"  From: {msg[1]} → To: {msg[2]}")
                print(f"  Encrypted (preview): {msg[3]}...")
                print(f"  Timestamp: {msg[4]}")
                print(f"  {'-' * 70}")
        else:
            print("\n  No messages sent yet.")
        
        # View Login Attempts
        print("\n" + "=" * 80)
        print("🔐 LOGIN ATTEMPTS TABLE (Audit Logs)")
        print("=" * 80)
        cursor.execute("""
            SELECT username, success, ip_address, created_at 
            FROM login_attempts 
            ORDER BY created_at DESC 
            LIMIT 10
        """)
        attempts = cursor.fetchall()
        
        if attempts:
            print(f"\nTotal Login Attempts: ", end="")
            cursor.execute("SELECT COUNT(*) FROM login_attempts")
            print(f"{cursor.fetchone()[0]} (showing last 10)\n")
            
            for attempt in attempts:
                status = "✅ SUCCESS" if attempt[1] else "❌ FAILED"
                print(f"  {status}")
                print(f"  Username: {attempt[0]}")
                print(f"  IP Address: {attempt[2]}")
                print(f"  Time: {attempt[3]}")
                print(f"  {'-' * 70}")
        else:
            print("\n  No login attempts logged yet.")
        
        # View Brute Force Logs
        print("\n" + "=" * 80)
        print("⚠️  BRUTE FORCE LOGS TABLE")
        print("=" * 80)
        cursor.execute("""
            SELECT attack_type, attempts, duration_ms, result, created_at 
            FROM brute_force_logs 
            ORDER BY created_at DESC 
            LIMIT 5
        """)
        brute_logs = cursor.fetchall()
        
        if brute_logs:
            print(f"\nTotal Brute Force Attacks: ", end="")
            cursor.execute("SELECT COUNT(*) FROM brute_force_logs")
            print(f"{cursor.fetchone()[0]} (showing last 5)\n")
            
            for log in brute_logs:
                print(f"  Attack Type: {log[0].upper()}")
                print(f"  Attempts: {log[1]}")
                print(f"  Duration: {log[2]:.2f} ms")
                print(f"  Result: {log[3].upper()}")
                print(f"  Time: {log[4]}")
                print(f"  {'-' * 70}")
        else:
            print("\n  No brute force attacks simulated yet.")
        
        print("\n" + "=" * 80)
        print("✅ Database viewing complete!")
        print("=" * 80)
        
        conn.close()
        
    except sqlite3.Error as e:
        print(f"\n❌ Database Error: {e}")
    except Exception as e:
        print(f"\n❌ Error: {e}")

if __name__ == "__main__":
    view_database()
