import sqlite3
conn = sqlite3.connect("/app/lab.db")
conn.executescript("""
    CREATE TABLE IF NOT EXISTS products (
        id INTEGER PRIMARY KEY, name TEXT, price REAL
    );
    INSERT OR IGNORE INTO products VALUES (1,'Widget',9.99);
    INSERT OR IGNORE INTO products VALUES (2,'Gadget',19.99);
""")
conn.commit(); conn.close()
print("DB ready.")
