import sqlite3

conn = sqlite3.connect("users.db")
cursor = conn.cursor()

# ✅ FIX: create table only if not exists
cursor.execute("""
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT,
    password TEXT
)
""")

# Optional: clear old data (for clean run)
cursor.execute("DELETE FROM users")

# Insert fresh data
cursor.execute("INSERT INTO users (username, password) VALUES ('admin', 'admin123')")

conn.commit()
conn.close()

print("Database ready")