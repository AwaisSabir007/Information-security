import sqlite3
import os

DB_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'secure_chat.db')

def migrate_stories():
    if not os.path.exists(DB_PATH):
        print(f"Database not found at {DB_PATH}")
        return

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    try:
        # Check if table exists
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='stories'")
        if not cursor.fetchone():
            print("Creating stories table...")
            cursor.execute("""
                CREATE TABLE stories (
                    id INTEGER PRIMARY KEY,
                    user_id INTEGER NOT NULL,
                    content_filename VARCHAR(120) NOT NULL,
                    caption VARCHAR(200),
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    expires_at DATETIME NOT NULL,
                    FOREIGN KEY (user_id) REFERENCES users(id)
                )
            """)
            cursor.execute("CREATE INDEX idx_stories_created_at ON stories(created_at)")
            cursor.execute("CREATE INDEX idx_stories_expires_at ON stories(expires_at)")
            print("Stories table created successfully.")
        else:
            print("Stories table already exists.")

        conn.commit()

    except Exception as e:
        print(f"An error occurred: {e}")
        conn.rollback()
    finally:
        conn.close()

if __name__ == "__main__":
    migrate_stories()
