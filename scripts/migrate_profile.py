import sqlite3
import os

DB_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'secure_chat.db')

def migrate():
    if not os.path.exists(DB_PATH):
        print(f"Database not found at {DB_PATH}")
        return

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    try:
        # Check if columns exist
        cursor.execute("PRAGMA table_info(users)")
        columns = [info[1] for info in cursor.fetchall()]

        if 'profile_picture' not in columns:
            print("Adding profile_picture column...")
            cursor.execute("ALTER TABLE users ADD COLUMN profile_picture VARCHAR(120)")
        else:
            print("profile_picture column already exists.")

        if 'bio' not in columns:
            print("Adding bio column...")
            cursor.execute("ALTER TABLE users ADD COLUMN bio VARCHAR(500)")
        else:
            print("bio column already exists.")

        conn.commit()
        print("Migration completed successfully.")

    except Exception as e:
        print(f"An error occurred: {e}")
        conn.rollback()
    finally:
        conn.close()

if __name__ == "__main__":
    migrate()
